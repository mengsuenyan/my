use crate::{error::MyError, ty::TableShow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt::Display, str::FromStr};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LangInfo {
    language: String,
    files: usize,
    codes: usize,
    comments: usize,
    blanks: usize,
}

impl LangInfo {
    pub fn new(lang: &str) -> Self {
        Self {
            language: lang.to_string(),
            files: 0,
            codes: 0,
            comments: 0,
            blanks: 0,
        }
    }

    pub fn set_lang(mut self, lang: &str) -> Self {
        self.language = lang.to_string();
        self
    }

    pub fn set_files(mut self, files: usize) -> Self {
        self.files = files;
        self
    }

    pub fn set_codes(mut self, codes: usize) -> Self {
        self.codes = codes;
        self
    }

    pub fn set_comments(mut self, comments: usize) -> Self {
        self.comments = comments;
        self
    }

    pub fn set_blanks(mut self, blanks: usize) -> Self {
        self.blanks = blanks;
        self
    }

    pub fn lines(&self) -> usize {
        self.blanks + self.codes + self.comments
    }

    fn to_vec_string(&self) -> Vec<String> {
        vec![
            self.language.clone(),
            self.files.to_string(),
            self.lines().to_string(),
            self.codes.to_string(),
            self.comments.to_string(),
            self.blanks.to_string(),
        ]
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CodeInfo {
    lang: Vec<LangInfo>,
}

impl CodeInfo {
    pub fn new() -> Self {
        Self { lang: vec![] }
    }

    pub fn is_empty(&self) -> bool {
        self.lang.is_empty()
    }

    pub fn add_lang(&mut self, lang: LangInfo) {
        self.lang.push(lang);
    }

    pub fn from_tokei_output(s: &str) -> Result<Self, MyError> {
        let Value::Object(json) =
            Value::from_str(s).map_err(|e| MyError::JsonParseFailed(format!("{e}")))?
        else {
            return Err(MyError::JsonParseFailed(
                "Tokei output is not json object".to_string(),
            ));
        };

        let mut code_info = Self::default();

        for (name, content) in json.iter() {
            let lang = LangInfo::new(name.as_str())
                .set_blanks(
                    content["blanks"]
                        .as_u64()
                        .map(|n| n as usize)
                        .unwrap_or_default(),
                )
                .set_codes(
                    content["code"]
                        .as_u64()
                        .map(|n| n as usize)
                        .unwrap_or_default(),
                )
                .set_comments(
                    content["comments"]
                        .as_u64()
                        .map(|n| n as usize)
                        .unwrap_or_default(),
                )
                .set_files(
                    content["reports"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or_default(),
                );

            code_info.add_lang(lang);
        }

        let len = code_info.lang.len();
        code_info.lang[0..len.saturating_sub(1)]
            .sort_by(|a, b| a.lines().cmp(&b.lines()).reverse());

        Ok(code_info)
    }
}

impl TableShow for CodeInfo {
    const COLS: usize = 6;

    fn head() -> Vec<String> {
        vec!["language", "files", "lines", "codes", "comments", "blanks"]
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn cols(&self) -> Vec<(String, Vec<String>)> {
        let mut res = (0..Self::COLS).map(|_| vec![]).collect::<Vec<_>>();

        for ele in self.lang.iter() {
            res.iter_mut()
                .zip(ele.to_vec_string().into_iter())
                .for_each(|(r, l)| r.push(l));
        }

        Self::head().into_iter().zip(res).collect()
    }
}

impl Display for CodeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.table().as_str())
    }
}
