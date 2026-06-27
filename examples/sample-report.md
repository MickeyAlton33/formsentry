# FormSentry report

> Example output. Form ids redacted. Generated with:
> `python3 formsentry.py https://forms.gle/EXAMPLE --md`

## Children's swimming-lesson registration

- **Target:** `https://forms.gle/EXAMPLE1`
- **Form id:** `1FAIpQLSc…REDACTED`
- **Overall risk:** **HIGH**

### Questions

| Required | Type | Question | PII |
|---|---|---|---|
|  | short_answer | Parent's name | full_name |
| ✅ | short_answer | Child's name | minor |
| ✅ | short_answer | Child's age | minor |
| ✅ | short_answer | Mobile phone number | phone |
|  | short_answer | Email address | email |
|  | multiple_choice | Membership status | |

### Findings

#### `HIGH` — Collects minors' / children's data
Question(s): “Child's name”; “Child's age”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects phone number
Question(s): “Mobile phone number”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → analyticsrestricted). Good.

---

## Example of a FAILING form (illustrative)

- **Overall risk:** **CRITICAL**

#### `CRITICAL` — Response summary is PUBLIC
The /viewanalytics endpoint returns HTTP 200 — 'See summary charts and text responses' is enabled, so anyone holding the form link can read every respondent's submitted answers.

> **Fix:** In the form: Responses → (⋮) menu → turn OFF 'See summary charts and text responses'.

#### `HIGH` — Collects national ID / passport
Question(s): “תעודת זהות”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.
