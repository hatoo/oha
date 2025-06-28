use std::str::FromStr;

///! Curl compatibility utilities

pub struct Form {
    pub boundary: String,
    pub parts: Vec<FormPart>,
}

pub struct FormPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

impl Form {
    pub fn new() -> Self {
        Self {
            boundary: Self::generate_boundary(),
            parts: Vec::new(),
        }
    }

    pub fn add_part(&mut self, part: FormPart) {
        self.parts.push(part);
    }

    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    pub fn body(&self) -> Vec<u8> {
        let mut body = Vec::new();

        for part in &self.parts {
            // Add boundary separator
            body.extend_from_slice(b"--");
            body.extend_from_slice(self.boundary.as_bytes());
            body.extend_from_slice(b"\r\n");

            // Add Content-Disposition header
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"");
            body.extend_from_slice(part.name.as_bytes());
            body.extend_from_slice(b"\"");

            // Add filename if present
            if let Some(filename) = &part.filename {
                body.extend_from_slice(b"; filename=\"");
                body.extend_from_slice(filename.as_bytes());
                body.extend_from_slice(b"\"");
            }
            body.extend_from_slice(b"\r\n");

            // Add Content-Type header if present
            if let Some(content_type) = &part.content_type {
                body.extend_from_slice(b"Content-Type: ");
                body.extend_from_slice(content_type.as_bytes());
                body.extend_from_slice(b"\r\n");
            }

            // Empty line before data
            body.extend_from_slice(b"\r\n");

            // Add the actual data
            body.extend_from_slice(&part.data);
            body.extend_from_slice(b"\r\n");
        }

        // Add final boundary
        body.extend_from_slice(b"--");
        body.extend_from_slice(self.boundary.as_bytes());
        body.extend_from_slice(b"--\r\n");

        body
    }
    fn generate_boundary() -> String {
        use rand::Rng;

        let mut rng = rand::rng();
        let random_bytes: [u8; 16] = rng.random();

        // Convert to hex string manually to avoid external hex dependency
        let hex_string = random_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        format!("----formdata-oha-{}", hex_string)
    }
}

impl FromStr for FormPart {
    type Err = anyhow::Error;

    /// Parse curl's -F format string
    /// Supports formats like:
    /// - `name=value`
    /// - `name=@filename` (file upload with filename)
    /// - `name=<filename` (file upload without filename)
    /// - `name=@filename;type=content-type`
    /// - `name=value;filename=name`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split on first '=' to separate name from value/options
        let (name, rest) = s
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("Invalid form format: missing '=' in '{}'", s))?;

        let name = name.to_string();

        // Parse the value part which may contain semicolon-separated options
        let parts: Vec<&str> = rest.split(';').collect();
        let value_part = parts[0];

        let mut filename = None;
        let mut content_type = None;
        let data;

        // Check if this is a file upload (@filename or <filename)
        if value_part.starts_with('@') {
            let file_path = &value_part[1..]; // Remove '@' prefix

            // Read file content
            data = std::fs::read(file_path)
                .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {}", file_path, e))?;

            // Extract filename from path
            filename = std::path::Path::new(file_path)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|s| s.to_string());
        } else if value_part.starts_with('<') {
            let file_path = &value_part[1..]; // Remove '<' prefix

            // Read file content
            data = std::fs::read(file_path)
                .map_err(|e| anyhow::anyhow!("Failed to read file '{}': {}", file_path, e))?;

            // Do not set filename for '<' format (curl behavior)
        } else {
            // Regular form field with string value
            data = value_part.as_bytes().to_vec();
        }

        // Parse additional options (filename, type, etc.)
        for part in parts.iter().skip(1) {
            if let Some((key, value)) = part.split_once('=') {
                match key.trim() {
                    "filename" => {
                        filename = Some(value.trim().to_string());
                    }
                    "type" => {
                        content_type = Some(value.trim().to_string());
                    }
                    _ => {
                        // Ignore unknown options for compatibility
                    }
                }
            }
        }

        Ok(FormPart {
            name,
            filename,
            content_type,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_field() {
        let part: FormPart = "name=value".parse().unwrap();
        assert_eq!(part.name, "name");
        assert_eq!(part.data, b"value");
        assert_eq!(part.filename, None);
        assert_eq!(part.content_type, None);
    }

    #[test]
    fn test_parse_field_with_filename() {
        let part: FormPart = "upload=data;filename=test.txt".parse().unwrap();
        assert_eq!(part.name, "upload");
        assert_eq!(part.data, b"data");
        assert_eq!(part.filename, Some("test.txt".to_string()));
        assert_eq!(part.content_type, None);
    }

    #[test]
    fn test_parse_field_with_type() {
        let part: FormPart = "data=content;type=text/plain".parse().unwrap();
        assert_eq!(part.name, "data");
        assert_eq!(part.data, b"content");
        assert_eq!(part.filename, None);
        assert_eq!(part.content_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_parse_field_with_filename_and_type() {
        let part: FormPart = "file=content;filename=test.txt;type=text/plain"
            .parse()
            .unwrap();
        assert_eq!(part.name, "file");
        assert_eq!(part.data, b"content");
        assert_eq!(part.filename, Some("test.txt".to_string()));
        assert_eq!(part.content_type, Some("text/plain".to_string()));
    }

    #[test]
    fn test_parse_invalid_format() {
        let result: Result<FormPart, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_file_upload() {
        // Create a temporary file for testing
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_form_upload.txt");
        std::fs::write(&test_file, b"test file content").unwrap();

        let form_str = format!("upload=@{}", test_file.display());
        let part: FormPart = form_str.parse().unwrap();

        assert_eq!(part.name, "upload");
        assert_eq!(part.data, b"test file content");
        assert_eq!(part.filename, Some("test_form_upload.txt".to_string()));
        assert_eq!(part.content_type, None);

        // Clean up
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_parse_file_upload_without_filename() {
        // Create a temporary file for testing
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_form_upload_no_filename.txt");
        std::fs::write(&test_file, b"test file content without filename").unwrap();

        let form_str = format!("upload=<{}", test_file.display());
        let part: FormPart = form_str.parse().unwrap();

        assert_eq!(part.name, "upload");
        assert_eq!(part.data, b"test file content without filename");
        assert_eq!(part.filename, None); // No filename set for '<' format
        assert_eq!(part.content_type, None);

        // Clean up
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_form_creation_and_body_generation() {
        let mut form = Form::new();

        // Add a simple text field
        let text_part: FormPart = "name=John".parse().unwrap();
        form.add_part(text_part);

        // Add a field with filename
        let file_part: FormPart = "file=content;filename=test.txt;type=text/plain"
            .parse()
            .unwrap();
        form.add_part(file_part);

        let body = form.body();
        let body_str = String::from_utf8_lossy(&body);

        // Check that boundary is present
        assert!(body_str.contains(&format!("--{}", form.boundary)));

        // Check Content-Disposition headers
        assert!(body_str.contains("Content-Disposition: form-data; name=\"name\""));
        assert!(
            body_str
                .contains("Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"")
        );

        // Check Content-Type header
        assert!(body_str.contains("Content-Type: text/plain"));

        // Check data content
        assert!(body_str.contains("John"));
        assert!(body_str.contains("content"));

        // Check final boundary
        assert!(body_str.ends_with(&format!("--{}--\r\n", form.boundary)));
    }

    #[test]
    fn test_form_content_type() {
        let form = Form::new();
        let content_type = form.content_type();

        assert!(content_type.starts_with("multipart/form-data; boundary="));
        assert!(content_type.contains(&form.boundary));
    }

    #[test]
    fn test_empty_form_body() {
        let form = Form::new();
        let body = form.body();
        let body_str = String::from_utf8_lossy(&body);

        // Should only contain final boundary for empty form
        assert_eq!(body_str, format!("--{}--\r\n", form.boundary));
    }

    #[test]
    fn test_form_with_file_upload() {
        // Create a temporary file for testing
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("form_test_upload.txt");
        std::fs::write(&test_file, b"file content for form").unwrap();

        let mut form = Form::new();

        // Parse and add file upload part
        let form_str = format!("upload=@{}", test_file.display());
        let file_part: FormPart = form_str.parse().unwrap();
        form.add_part(file_part);

        let body = form.body();
        let body_str = String::from_utf8_lossy(&body);

        // Check file upload formatting
        assert!(body_str.contains(
            "Content-Disposition: form-data; name=\"upload\"; filename=\"form_test_upload.txt\""
        ));
        assert!(body_str.contains("file content for form"));

        // Clean up
        std::fs::remove_file(&test_file).ok();
    }

    #[test]
    fn test_boundary_generation_is_random() {
        let form1 = Form::new();
        let form2 = Form::new();

        // Boundaries should be different for different forms
        assert_ne!(form1.boundary, form2.boundary);

        // Boundaries should follow the expected format
        assert!(form1.boundary.starts_with("----formdata-oha-"));
        assert!(form2.boundary.starts_with("----formdata-oha-"));

        // Boundaries should have the expected length (prefix + 32 hex chars)
        assert_eq!(form1.boundary.len(), "----formdata-oha-".len() + 32);
        assert_eq!(form2.boundary.len(), "----formdata-oha-".len() + 32);
    }
}
