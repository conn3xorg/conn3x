# Hand-written module pages

`moddoc` builds each module's reference page from the provider schema. A file
here named after a module (`file.md`, `package.md`) adds the parts a schema
can't: an introduction and examples, placed after the description in place of
the generated example, and notes after the reference, separated by a line:

    <!-- reference -->

Every ```hcl block must be complete `step` and `probe` blocks, which the
docs examples test wraps in a circuit, or a whole `circuit` block; the test
checks each one validates.
