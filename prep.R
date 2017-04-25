library(rvest)
library(stringi)
library(tidyverse)

pg <- read_html("https://www.cvedetails.com/cvss-score-distribution.php")
html_nodes(pg, "table.grid") %>%
  html_table(header=TRUE) %>%
  .[[1]] %>%
  set_names(stri_replace_all_fixed(tolower(colnames(.)), " ", "_")) %>%
  slice(1:10) %>%
  mutate(pct = as.numeric(percentage)/100) -> cvss_df

set.seed(1492)
sample(cvss_df$cvss_score, 100, replace=TRUE, prob=cvss_df$pct) %>%
  sprintf("{ score:'%s', v:'visible', index }", .) %>%
  paste0(collapse=",") %>%
  sprintf("[ %s ]", .)

n <- 1000

set.seed(1492)
sample(cvss_df$cvss_score, n*3, replace=TRUE, prob=cvss_df$pct) %>%
  sort() %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/unknown.json")

set.seed(1492)
sample(cvss_df$cvss_score, n, replace=TRUE, prob=cvss_df$pct) %>%
  sort() %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/all.json")

set.seed(1492)
sample(cvss_df$cvss_score, n*0.6, replace=TRUE, prob=cvss_df$pct) %>%
  sort() %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/vulndb.json")

set.seed(1492)
sample(cvss_df$cvss_score, n*0.2, replace=TRUE, prob=cvss_df$pct) %>%
  sort() %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/cve.json")



# All: 1000
# Vuln: 80%
# CVE: 60%
100 = 0.6 * x1

600/3
