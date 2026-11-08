# Using AI tools

You can use AI tools to help you contribute to Conn3x: to write code, tests, docs or a circuit. We don't ban them anywhere. What we care about is that a person stands behind everything that lands, so the rules are about checking, not about tools.

## Pull requests

You're responsible for every line in your PR, however it was written.

- Understand it. If a reviewer asks why a line is there, you should be able to answer without asking the tool.
- Run it. The tests pass on your machine, and anything the PR says works, you've seen work.
- Sign it off. Your `Signed-off-by` line is the [DCO](https://developercertificate.org): you're saying you have the right to submit the change under the project's license. That holds for AI-assisted work too, so don't submit output from a tool whose terms don't let you.
- Keep it small and on topic, like any other PR. A tool makes it easy to change forty files; a reviewer still has to read them.

PRs that were clearly generated and never run, the kind that touch code nobody asked about or fail CI on the first push, get closed with a link to this page. Fix it up and open it again; that's welcome.

## Security reports

A report to security@conn3x.org or through private vulnerability reporting needs a person who has reproduced the problem. Please don't paste a scanner's or a chatbot's findings without checking them first: show us the steps, and the version you ran them on. See [SECURITY.md](SECURITY.md).

## Issues, discussions and reviews

- Write in your own words, or check every word you didn't write.
- Commands, configs and error messages you post should be ones you actually ran or saw.
- When you answer someone's question with a tool's help, make sure the answer is right for Conn3x, not for Terraform or Ansible in general.

## Disclosure

You don't have to say you used a tool. If it helps a reviewer, for example "the parser was drafted with an assistant and I rewrote the error handling", feel free to.
