resource "test_resource" "foo" {
  value = "bar"
}

resource "test_resource" "always" {
  value = timestamp()
}
