pub(crate) fn to_upper_remove_seperators(val: &str) -> String {
    val.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .map(|c| c.to_uppercase())
        .flat_map(|c| c)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_seperators() {
        let s = "A B-C_D";
        let s = to_upper_remove_seperators(s);
        assert_eq!(s, "ABCD");
    }
}
