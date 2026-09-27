pub fn is_domain_in_white_list(domain: &String, content: &Vec<String>) -> bool{
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

pub fn is_domain_rus(domain: &String) -> bool{
    let domain = domain.to_lowercase();
    if domain.ends_with(".ru") || domain.ends_with(".рф") {
        return true;
    }else {
        return false;
    }
}