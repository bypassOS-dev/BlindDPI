pub fn is_domain_in_white_list(domain: &str, content: &[String]) -> bool{
    let domain = domain.to_lowercase();

    for line in content {
        if domain == *line {
            return true;
        } 
        if let Some(prefix) = domain.strip_suffix(line) {
            if prefix.ends_with(".") {
                return true;
            }
        }
    }
    false
}
