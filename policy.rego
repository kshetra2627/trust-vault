package trustvault

default allow = false

allow {
  input.role == "admin"
}

allow {
  input.role == "user"
  input.action == "read"
}

allow {
  input.role == "user"
  input.action == "upload"
}