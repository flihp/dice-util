Testing often requires that we generate various artifacts used in the
attestation API. It's possible to use a live system to generate these artifacts
and then use them in testing but this doesn't give us much control: We can use
them unmodified which limits what we can test, or we can modify them by hand
which is error prone and annoying.

The alternative is to generate these artifacts from a specification. For
complex structures like the cert chain this can be a lot of work (see
[pki-playground](https://github.com/oxidecomputer/pki-playground)), but the
`Log` is pretty simple. This project contains source code to generate an
attestation `Log` from a KDL document.
