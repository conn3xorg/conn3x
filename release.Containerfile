# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# The release image, built by GoReleaser from its own binaries.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/conn3x /usr/local/bin/conn3x
ENTRYPOINT ["/usr/local/bin/conn3x"]
