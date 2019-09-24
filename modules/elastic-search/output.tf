output "es_domain" {
    value = "${aws_elasticsearch_domain.es_domain.domain_name}"
}
output "kibana_es" {
    value = "${aws_elasticsearch_domain.es_domain.kibana_endpoint}"
}