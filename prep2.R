library(rvest)
library(broom)
library(stringi)
library(jsonlite)
library(tidyverse)

pg <- read_html("https://www.cvedetails.com/cvss-score-distribution.php")
html_nodes(pg, "table.grid") %>%
  html_table(header=TRUE) %>%
  .[[1]] %>%
  set_names(stri_replace_all_fixed(tolower(colnames(.)), " ", "_")) %>%
  slice(1:10) %>%
  mutate(pct = as.numeric(percentage)/100) -> cvss_df

make_parts <- function(vec, nam) {

  all_scores <- c("0-1", "1-2", "2-3", "3-4", "4-5", "5-6", "6-7", "7-8", "8-9", "9-10")

  set.seed(1)
  foss <- sample(vec, length(vec)*0.10)
  set.seed(1492)
  foreign <- sample(vec, length(vec) * 0.01)
  medical <- sample(vec, length(vec)*0.05)
  ics <- sample(vec, length(vec)*0.10)
  enterprise <- sample(vec, length(vec)*0.65)

  foreign <- table(foreign) %>% tidy() %>% rename(score=foreign, n=Freq) %>%
      mutate(score = as.character(score)) %>% complete(score=all_scores, fill=list(n=0))

  oss <- table(foss) %>% tidy() %>% rename(score=foss, n=Freq) %>%
      mutate(score = as.character(score)) %>% complete(score=all_scores, fill=list(n=0))

  medical <- table(medical) %>% tidy() %>% rename(score=medical, n=Freq) %>%
      mutate(score = as.character(score)) %>% complete(score=all_scores, fill=list(n=0))

  ics <- table(ics) %>% tidy() %>% rename(score=ics, n=Freq) %>%
      mutate(score = as.character(score)) %>% complete(score=all_scores, fill=list(n=0))

  enterprise <- table(enterprise) %>% tidy() %>% rename(score=enterprise, n=Freq) %>%
      mutate(score = as.character(score)) %>% complete(score=all_scores, fill=list(n=0))

  max_val <- max(c(foreign$n, oss$n, medical$n, ics$n, enterprise$n))

  list(
    foreign=foreign, oss=oss, medical=medical, ics=ics, enterprise=enterprise, max_val=max_val
  ) %>% toJSON() %>% cat(sep="", file=sprintf("json/%s_extract_8060.json", nam))

}

n <-  1000

set.seed(1492)
unknown <- sample(cvss_df$cvss_score, n*3, replace=TRUE, prob=cvss_df$pct)
sort(unknown) %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/unknown_8060.json")
make_parts(unknown, "unknown")

set.seed(1492)
known <- sample(cvss_df$cvss_score, n, replace=TRUE, prob=cvss_df$pct)
sort(known) %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/all_8060.json")
make_parts(known, "all")

set.seed(1492)
# vulndb <- sample(cvss_df$cvss_score, n*0.8, replace=TRUE, prob=cvss_df$pct)
vulndb <- sample(known, length(known)*0.8, replace=FALSE)
sort(vulndb) %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/vulndb_8060.json")
make_parts(vulndb, "vulndb")

set.seed(1492)
# cve <- sample(cvss_df$cvss_score, n*0.6, replace=TRUE, prob=cvss_df$pct)
cve <- sample(vulndb, length(vulndb)*0.6, replace=FALSE)
sort(cve) %>%
  sprintf('{ "s":"%s" }', .) %>%
  paste0(collapse=", ") %>%
  sprintf("[ %s ]", .) %>% write_lines("json/cve_8060.json")
make_parts(cve, "cve")

