# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
"""Tests for gen_watchlist.py: reading defaults and updating only them. No network."""

import copy
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_watchlist as g  # noqa: E402

SRC = '''
variable "traefik_version" {
  type        = string
  default     = "3.7.20"
  description = "Traefik release, such as \\"3.7.20\\"."

  validation {
    condition     = can(regex("^[0-9]+{1,3}$", var.traefik_version))
    error_message = "a version"
  }
}

variable "java_version" {
  type    = number
  default = 25
}

variable "release" {
  type = object({
    tag    = string
    sha256 = string
  })
  default = {
    tag    = "4.20.0_okd_scos.16"
    sha256 = "abc"
  }
}

variable "computed" {
  default = "${var.java_version}-x"
}

locals {
  # A comment with a { brace.
  version = "2.11.7"
}
'''


class Read(unittest.TestCase):
    def test_variable_number_object_field_and_local(self):
        self.assertEqual(g.default_of(SRC, "traefik_version"), "3.7.20")
        self.assertEqual(g.default_of(SRC, "java_version"), "25")
        self.assertEqual(g.default_of(SRC, "release.tag"), "4.20.0_okd_scos.16")
        self.assertEqual(g.default_of(SRC, "local.version"), "2.11.7")

    def test_computed_or_missing_is_none(self):
        self.assertIsNone(g.default_of(SRC, "computed"))
        self.assertIsNone(g.default_of(SRC, "missing"))
        self.assertIsNone(g.default_of(SRC, "local.missing"))
        self.assertIsNone(g.default_of(SRC, "release.missing"))


class Update(unittest.TestCase):
    WL = {"generated": "x", "ecosystems": ["Debian:13"], "feeds": [], "unsure": [{"circuit": "c"}],
          "entries": [{"name": "traefik", "circuits": ["circuit-traefik"], "packages": ["traefik"], "osv": [], "github": ["traefik/traefik"],
                       "images": [], "pinned": [{"circuit": "circuit-traefik", "variable": "traefik_version", "default": "3.7.16"},
                                                {"circuit": "circuit-gone", "variable": "v", "default": "1.0"}]}]}

    def test_only_defaults_change(self):
        wl = copy.deepcopy(self.WL)
        changes = g.update(wl, lambda c, v: g.default_of(SRC, v) if c == "circuit-traefik" else None)
        self.assertEqual(changes, [("circuit-traefik", "traefik_version", "3.7.16", "3.7.20")])
        want = copy.deepcopy(self.WL)
        want["entries"][0]["pinned"][0]["default"] = "3.7.20"
        # A circuit that couldn't be read keeps its old default.
        self.assertEqual(wl, want)


if __name__ == "__main__":
    unittest.main()
