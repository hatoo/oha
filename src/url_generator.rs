use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
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
    ParseError(ParseError, String),
    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("No valid URLs found")]
    NoURLsError(),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl UrlGenerator {
    pub fn new_static(url: Url) -> Self {
        Self::Static(url)
    }

    pub fn new_multi_static(filename: &str) -> Result<Self, UrlGeneratorError> {
        let path = Path::new(filename);
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);

        let urls: Vec<Url> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .map(|url_str| {
                Url::parse(&url_str).map_err(|e| {
                    UrlGeneratorError::ParseError(
                        e,
                        format!("Failed to parse URL '{}': {}", url_str, e),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self::MultiStatic(urls))
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
                    Err(UrlGeneratorError::NoURLsError())
                }
            }
            Self::Dynamic(regex) => {
                let generated = Distribution::<Result<String, FromUtf8Error>>::sample(regex, rng)?;
                Ok(Cow::Owned(Url::parse(generated.as_str()).map_err(|e| {
                    UrlGeneratorError::ParseError(e, generated)
                })?))
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
    use std::{fs, net::Ipv4Addr};
    use tempfile::NamedTempFile;
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
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let urls = vec![
            "http://127.0.0.1/a1",
            "http://127.0.0.1/b2",
            "http://127.0.0.1/c3",
        ];
        let file_content = urls.join("\n") + "\n\n";
        fs::write(temp_file.path(), file_content).expect("Failed to write to temporary file");

        let url_generator =
            UrlGenerator::new_multi_static(temp_file.path().to_str().unwrap()).unwrap();

        for _ in 0..10 {
            let url = url_generator.generate(&mut thread_rng()).unwrap();
            assert_eq!(url.host(), Some(Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1))));
            assert!(urls.contains(&url.as_str()));
        }
    }

    #[test]
    fn test_url_generator_multistatic_errors() {
        let temp_file = NamedTempFile::new().expect("Failed to create temporary file");
        let file_content = "https://127.0.0.1\n\nno url\n";
        fs::write(temp_file.path(), file_content).expect("Failed to write to temporary file");

        let url_generator = UrlGenerator::new_multi_static(temp_file.path().to_str().unwrap());

        assert!(
            url_generator.is_err(),
            "Parsing should have failed with an error!"
        );
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
}
