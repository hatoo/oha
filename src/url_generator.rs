use std::{borrow::Cow, string::FromUtf8Error};

use rand::prelude::*;
use rand_regex::Regex;
use thiserror::Error;
use url::{ParseError, Url};

#[derive(Clone, Debug)]
pub enum UrlGenerator {
    Static(Url),
    Dynamic(Regex),
}

#[derive(Error, Debug)]
pub enum UrlGeneratorError {
    #[error("{0}, generated url: {1}")]
    ParseError(ParseError, String),
    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl UrlGenerator {
    pub fn new_static(url: Url) -> Self {
        Self::Static(url)
    }

    pub fn new_dynamic(regex: Regex) -> Self {
        Self::Dynamic(regex)
    }

    pub fn generate<R: Rng>(&self, rng: &mut R) -> Result<Cow<Url>, UrlGeneratorError> {
        match self {
            Self::Static(url) => Ok(Cow::Borrowed(url)),
            Self::Dynamic(regex) => {
                let generated = Distribution::<Result<String, FromUtf8Error>>::sample(regex, rng)?;
                Ok(Cow::Owned(Url::parse(generated.as_str()).map_err(|e| {
                    UrlGeneratorError::ParseError(e, generated)
                })?))
            }
        }
    }
}
