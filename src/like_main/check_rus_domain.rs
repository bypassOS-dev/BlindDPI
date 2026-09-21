pub async fn is_domain_rus(domain: &String) -> bool{
    let domain = domain.to_lowercase();
    if domain.ends_with(".ru") || domain.ends_with(".рф") {
        return true;
    }else {
        return false;
    }

}