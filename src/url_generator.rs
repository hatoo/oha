use std::{borrow::Cow, string::FromUtf8Error};

use rand::prelude::*;
use rand::seq::SliceRandom;
use rand_regex::Regex;
use thiserror::Error;
use url::{ParseError, Url};

#[derive(Clone, Debug)]
pub enum UrlGenerator {
    Static(Url),
    MultiStatic(Vec<Url>),
    Dynamic(Regex),
}

#[derive(Error, Debug)]
pub enum UrlGeneratorError {
    #[error("{0}, generated url: {1}")]
    Parse(ParseError, String),
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),
    #[error("No valid URLs found")]
    NoURLs(),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl UrlGenerator {
    pub fn new_static(url: Url) -> Self {
        Self::Static(url)
    }

    pub fn new_multi_static(urls: Vec<Url>) -> Self {
        assert!(!urls.is_empty());
        Self::MultiStatic(urls)
    }

    pub fn new_dynamic(regex: Regex) -> Self {
        Self::Dynamic(regex)
    }

    pub fn generate<R: Rng>(&self, rng: &mut R) -> Result<Cow<Url>, UrlGeneratorError> {
        match self {
            Self::Static(url) => Ok(Cow::Borrowed(url)),
            Self::MultiStatic(urls) => {
                if let Some(random_url) = urls.choose(rng) {
                    Ok(Cow::Borrowed(random_url))
                } else {
                    Err(UrlGeneratorError::NoURLs())
                }
            }
            Self::Dynamic(regex) => {
                let generated = Distribution::<Result<String, FromUtf8Error>>::sample(regex, rng)?;
                Ok(Cow::Owned(
                    Url::parse(generated.as_str())
                        .map_err(|e| UrlGeneratorError::Parse(e, generated))?,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pcg64si::Pcg64Si;

    use super::*;
    use rand_regex::Regex as RandRegex;
    use regex::Regex;
    use std::net::Ipv4Addr;
    use url::{Host, Url};

    #[test]
    fn test_url_generator_static() {
        let url_generator = UrlGenerator::new_static(Url::parse("http://127.0.0.1/test").unwrap());
        let url = url_generator.generate(&mut thread_rng()).unwrap();
        assert_eq!(url.host(), Some(Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(url.path(), "/test");
    }

    #[test]
    fn test_url_generator_multistatic() {
        let urls = [
            "http://127.0.0.1/a1",
            "http://127.0.0.1/b2",
            "http://127.0.0.1/c3",
        ];

        let url_generator =
            UrlGenerator::new_multi_static(urls.iter().map(|u| Url::parse(u).unwrap()).collect());

        for _ in 0..10 {
            let url = url_generator.generate(&mut thread_rng()).unwrap();
            assert_eq!(url.host(), Some(Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1))));
            assert!(urls.contains(&url.as_str()));
        }
    }

    #[test]
    fn test_url_generator_dynamic() {
        let path_regex = "/[a-z][a-z][0-9]";
        let url_generator = UrlGenerator::new_dynamic(
            RandRegex::compile(&format!(r"http://127\.0\.0\.1{path_regex}"), 4).unwrap(),
        );
        let url = url_generator.generate(&mut thread_rng()).unwrap();
        assert_eq!(url.host(), Some(Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(Regex::new(path_regex)
            .unwrap()
            .captures(url.path())
            .is_some());
    }

    #[test]
    fn test_url_generator_dynamic_consistency() {
        let url_generator = UrlGenerator::new_dynamic(
            RandRegex::compile(r"http://127\.0\.0\.1/[a-z][a-z][0-9]", 4).unwrap(),
        );

        for _ in 0..100 {
            let rng: Pcg64Si = SeedableRng::from_entropy();

            assert_eq!(
                url_generator.generate(&mut rng.clone()).unwrap(),
                url_generator.generate(&mut rng.clone()).unwrap()
            );
        }
    }

    #[test]
    fn test_url_generator_multi_consistency() {
        let urls = [
            "http://example.com/a1",
            "http://example.com/a2",
            "http://example.com/a3",
            "http://example.com/a4",
            "http://example.com/a5",
        ];
        let url_generator =
            UrlGenerator::new_multi_static(urls.iter().map(|u| Url::parse(u).unwrap()).collect());

        for _ in 0..100 {
            let rng: Pcg64Si = SeedableRng::from_entropy();

            assert_eq!(
                url_generator.generate(&mut rng.clone()).unwrap(),
                url_generator.generate(&mut rng.clone()).unwrap()
            );
        }
    }
}
