use std::{borrow::Cow, str::FromStr, string::FromUtf8Error};

use http::{uri::InvalidUri, Uri};
use rand::prelude::*;
use rand_regex::Regex;
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum UrlGenerator {
    Static(Uri),
    Dynamic(Regex),
}

#[derive(Error, Debug)]
pub enum UrlGeneratorError {
    #[error(transparent)]
    InvalidUri(#[from] InvalidUri),
    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
}

impl UrlGenerator {
    pub fn new_static(url: Uri) -> Self {
        Self::Static(url)
    }

    pub fn new_dynamic(regex: Regex) -> Self {
        Self::Dynamic(regex)
    }

    pub fn generate<R: Rng>(&self, rng: &mut R) -> Result<Cow<Uri>, UrlGeneratorError> {
        match self {
            Self::Static(url) => Ok(Cow::Borrowed(&url)),
            Self::Dynamic(regex) => Ok(Cow::Owned(Uri::from_str(
                Distribution::<Result<String, FromUtf8Error>>::sample(regex, rng)?.as_str(),
            )?)),
        }
    }
}
