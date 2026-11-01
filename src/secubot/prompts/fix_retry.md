## Verification failed (attempt {attempt} of {max_attempts})

The pipeline checked your change and it did not pass:

{problems}

<untrusted>
### Output from the failing step (tail)

{output}
</untrusted>

Adjust your change so that the finding is resolved, the project builds and the existing
tests pass, staying within the same scope rules. Your previous edits are still in the
working tree. If the problem cannot be solved within the rules, make no further edits and
explain in `blocked_reason`. Answer with the JSON object required by the output schema.
