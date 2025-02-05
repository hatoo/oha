use rustls_pki_types::pem::PemObject;

#[cfg(feature = "rustls")]
pub struct RuslsConfigs {
    no_alpn: std::sync::Arc<rustls::ClientConfig>,
    alpn_h2: std::sync::Arc<rustls::ClientConfig>,
}

#[cfg(feature = "rustls")]
impl RuslsConfigs {
    pub fn new(
        insecure: bool,
        cacert_pem: Option<&[u8]>,
        client_auth: Option<(&[u8], &[u8])>,
    ) -> Self {
        use std::sync::Arc;

        let mut root_cert_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            root_cert_store.add(cert).unwrap();
        }

        if let Some(cacert_pem) = cacert_pem {
            for der in rustls_pki_types::CertificateDer::pem_slice_iter(cacert_pem) {
                root_cert_store.add(der.unwrap()).unwrap();
            }
        }

        let builder = rustls::ClientConfig::builder().with_root_certificates(root_cert_store);

        let mut config = if let Some((cert, key)) = client_auth {
            let certs = rustls_pki_types::CertificateDer::pem_slice_iter(cert)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key).unwrap();

            builder.with_client_auth_cert(certs, key).unwrap()
        } else {
            builder.with_no_client_auth()
        };
        if insecure {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(AcceptAnyServerCert));
        }

        let mut no_alpn = config.clone();
        no_alpn.alpn_protocols = vec![];
        let mut alpn_h2 = config;
        alpn_h2.alpn_protocols = vec![b"h2".to_vec()];
        Self {
            no_alpn: Arc::new(no_alpn),
            alpn_h2: Arc::new(alpn_h2),
        }
    }

    pub fn config(&self, is_http2: bool) -> &std::sync::Arc<rustls::ClientConfig> {
        if is_http2 {
            &self.alpn_h2
        } else {
            &self.no_alpn
        }
    }
}

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
pub struct NativeTlsConnectors {
    pub no_alpn: tokio_native_tls::TlsConnector,
    pub alpn_h2: tokio_native_tls::TlsConnector,
}

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
impl NativeTlsConnectors {
    pub fn new(insecure: bool) -> Self {
        let new = |is_http2: bool| {
            let mut connector_builder = native_tls::TlsConnector::builder();
            if insecure {
                connector_builder
                    .danger_accept_invalid_certs(true)
                    .danger_accept_invalid_hostnames(true);
            }

            if is_http2 {
                connector_builder.request_alpns(&["h2"]);
            }

            connector_builder
                .build()
                .expect("Failed to build native_tls::TlsConnector")
                .into()
        };

        Self {
            no_alpn: new(false),
            alpn_h2: new(true),
        }
    }

    pub fn connector(&self, is_http2: bool) -> &tokio_native_tls::TlsConnector {
        if is_http2 {
            &self.alpn_h2
        } else {
            &self.no_alpn
        }
    }
}

/// A server certificate verifier that accepts any certificate.
#[cfg(feature = "rustls")]
#[derive(Debug)]
pub struct AcceptAnyServerCert;

#[cfg(feature = "rustls")]
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .unwrap()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
