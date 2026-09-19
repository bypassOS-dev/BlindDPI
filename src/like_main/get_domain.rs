async fn _is_damain_in_white_list(domain: &str, content: &Vec<String>) -> bool{
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
    return false;
}