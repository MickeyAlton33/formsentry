# FormSentry — mass analysis summary

- **Forms assessed:** 13
- **Worst risk:** **HIGH**
- **By risk:** 2 high, 11 medium
- **PII categories seen (forms):** phone number (13), name (12), date of birth (10), email address (4), minors' / children's data (2)

## Needs attention (medium+)

| Risk | Form |
|---|---|
| **HIGH** | רישום לאימוני שחייה  לילדים |
| **HIGH** | רישום לאימוני שחייה אישיים |
| **MEDIUM** | רשימת חזרה ללא התחייבות זמן |
| **MEDIUM** | רישום לפילאטיס מכשירים לידים חמים |
| **MEDIUM** | דרוש.ה: מנהל.ת תחום פילאטיס מכשירים |
| **MEDIUM** | דרושים לסטודיו |
| **MEDIUM** | דרושים.ות- נציגי ונציגות שירות ומכירה  |
| **MEDIUM** | דרושים.ות- נציגי שירות ומכירה/קוסמטיקאית/מניקוריסטית לספא |
| **MEDIUM** | דרושים.ות- נציגי ונציגות קבלה  |
| **MEDIUM** | דרוש.ה קוסמטיקאי.ת |
| **MEDIUM** | דרושים-מאמנים ומאמנות לחדר הכושר |
| **MEDIUM** |  דרוש.ה מניקוריסט.ית |
| **MEDIUM** | דרושים מצילי בריכה ומדריכי שחייה |

# FormSentry report

## רישום לאימוני שחייה  לילדים

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLScTkf_qpV3lnY1AeAygWsdNZ5wCpVI22MQWznu92Hq3nmyPCA/viewform`
- **Form id:** `1FAIpQLScTkf_qpV3lnY1AeAygWsdNZ5wCpVI22MQWznu92Hq3nmyPCA`
- **Overall risk:** **HIGH**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם ההורה |  |
|  | short_answer | שם הילד/ה | minor |
| ✅ | short_answer | גיל הילד/ה | minor, dob |
| ✅ | short_answer | מה מספר הטלפון הנייד שלך? | phone |
| ✅ | multiple_choice | באיזה סוג אימון את/ה מתעניין/נת? |  |
| ✅ | short_answer | מה כתובת המייל שלך? | email |
| ✅ | multiple_choice | האם את/ה מנוי/ה? |  |

### Findings
#### `HIGH` — Collects minors' / children's data
Question(s): “שם הילד/ה”; “גיל הילד/ה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “גיל הילד/ה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון הנייד שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLScTkf_qpV3lnY1AeAygWsdNZ5wCpVI22MQWznu92Hq3nmyPCA/analyticsrestricted). Good.

## רישום לאימוני שחייה אישיים

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSfmg7IqXrpQ0Eu5m-ILQyTJKCK8nPh4li0RDUHUMs1tqp9PLg/viewform`
- **Form id:** `1FAIpQLSfmg7IqXrpQ0Eu5m-ILQyTJKCK8nPh4li0RDUHUMs1tqp9PLg`
- **Overall risk:** **HIGH**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | multiple_choice | האם את/ה מנוי/ה? |  |
|  | short_answer | מה שמך? | full_name |
|  | short_answer | מה גילך (או גיל הילד)? | minor, dob |
|  | short_answer | מה מספר הטלפון הנייד שלך? | phone |
|  | short_answer | מה כתובת המייל שלך? | email |

### Findings
#### `HIGH` — Collects minors' / children's data
Question(s): “מה גילך (או גיל הילד)?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “מה גילך (או גיל הילד)?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון הנייד שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSfmg7IqXrpQ0Eu5m-ILQyTJKCK8nPh4li0RDUHUMs1tqp9PLg/analyticsrestricted). Good.

## רשימת חזרה ללא התחייבות זמן

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSfeuxsGUTn34Y9wVXmm3_bQzF0x9k_lYpnF7sgbzsSNa3HICQ/viewform`
- **Form id:** `1FAIpQLSfeuxsGUTn34Y9wVXmm3_bQzF0x9k_lYpnF7sgbzsSNa3HICQ`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
|  | short_answer | מה שמך המלא? | full_name |
|  | short_answer | מה מספר הטלפון הנייד שלך? | phone |
|  | short_answer | מה כתובת המייל שלך? | email |
|  | multiple_choice | איזה סוג מנוי תרצה/י לעשות? |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון הנייד שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSfeuxsGUTn34Y9wVXmm3_bQzF0x9k_lYpnF7sgbzsSNa3HICQ/analyticsrestricted). Good.

## רישום לפילאטיס מכשירים לידים חמים

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSfI6edSXDmX1fSWfOc6o3ujsgTEB_DWTZsE6DSChvTgUl-vDw/viewform`
- **Form id:** `1FAIpQLSfI6edSXDmX1fSWfOc6o3ujsgTEB_DWTZsE6DSChvTgUl-vDw`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | multiple_choice | האם את/ה מנוי/ה? |  |
| ✅ | short_answer | מה שמך? | full_name |
| ✅ | short_answer | מה גילך? | dob |
| ✅ | short_answer | מה מספר הטלפון הנייד שלך? | phone |
|  | short_answer | מה כתובת המייל שלך? | email |
| ✅ | multiple_choice | לנשים - האם את מתעניינת בפילאטיס להריון או לאחר לידה? |  |

### Findings
#### `MEDIUM` — Collects date of birth
Question(s): “מה גילך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון הנייד שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSfI6edSXDmX1fSWfOc6o3ujsgTEB_DWTZsE6DSChvTgUl-vDw/analyticsrestricted). Good.

## דרוש.ה: מנהל.ת תחום פילאטיס מכשירים

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLScvUML7K5IAKZCyTxcBNiLrRcMHw9G49ognA8RdShJkuySZUg/viewform`
- **Form id:** `1FAIpQLScvUML7K5IAKZCyTxcBNiLrRcMHw9G49ognA8RdShJkuySZUg`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
|  | short_answer | מה שמך? | full_name |
|  | short_answer | מה מספר הטלפון הנייד שלך? | phone |
|  | paragraph | ספר.י לנו קצת על עצמך? האם יש לך נסיון רלוונטי בתחום? |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון הנייד שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLScvUML7K5IAKZCyTxcBNiLrRcMHw9G49ognA8RdShJkuySZUg/analyticsrestricted). Good.

## דרושים לסטודיו

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSe3Deta33jLt1XcmMOB-JQiu3PN8LrF6CLRAmQPe98Wlp2Oog/viewform`
- **Form id:** `1FAIpQLSe3Deta33jLt1XcmMOB-JQiu3PN8LrF6CLRAmQPe98Wlp2Oog`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | מה שמך (שם פרטי ומשפחה)? | full_name |
| ✅ | short_answer | מה מספר הטלפון שלך? | phone |
| ✅ | short_answer | אילו שיעורים את.ה מעביר.ה? |  |
| ✅ | short_answer | כמה שנות נסיון יש לך? |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מה מספר הטלפון שלך?”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSe3Deta33jLt1XcmMOB-JQiu3PN8LrF6CLRAmQPe98Wlp2Oog/analyticsrestricted). Good.

## דרושים.ות- נציגי ונציגות שירות ומכירה 

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSduKlTZ48he34PM8ZdIb77QBn44ijeP-HMfmv1ggiWD7PccBw/viewform`
- **Form id:** `1FAIpQLSduKlTZ48he34PM8ZdIb77QBn44ijeP-HMfmv1ggiWD7PccBw`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSduKlTZ48he34PM8ZdIb77QBn44ijeP-HMfmv1ggiWD7PccBw/analyticsrestricted). Good.

## דרושים.ות- נציגי שירות ומכירה/קוסמטיקאית/מניקוריסטית לספא

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSeoePYE8NxireNjEhczSNjloG7-oXQL8ZzrfFLgZNdYMb2VeA/viewform`
- **Form id:** `1FAIpQLSeoePYE8NxireNjEhczSNjloG7-oXQL8ZzrfFLgZNdYMb2VeA`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSeoePYE8NxireNjEhczSNjloG7-oXQL8ZzrfFLgZNdYMb2VeA/analyticsrestricted). Good.

## דרושים.ות- נציגי ונציגות קבלה 

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLScDnmIQPr-QhvTwe0yDnl1LG8R6WCMCw-YcfdyW0hFp_2fAqg/viewform`
- **Form id:** `1FAIpQLScDnmIQPr-QhvTwe0yDnl1LG8R6WCMCw-YcfdyW0hFp_2fAqg`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLScDnmIQPr-QhvTwe0yDnl1LG8R6WCMCw-YcfdyW0hFp_2fAqg/analyticsrestricted). Good.

## דרוש.ה קוסמטיקאי.ת

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLScM-7R5trmNMzNVI7gxzreLc5lAk1AyOrXE-XwMJL_pTqlfDg/viewform`
- **Form id:** `1FAIpQLScM-7R5trmNMzNVI7gxzreLc5lAk1AyOrXE-XwMJL_pTqlfDg`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLScM-7R5trmNMzNVI7gxzreLc5lAk1AyOrXE-XwMJL_pTqlfDg/analyticsrestricted). Good.

## דרושים-מאמנים ומאמנות לחדר הכושר

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSc-ubmmEowkPO6XiQaafdj7XzOBLSZoMmvaCghQxx6ZaQV17g/viewform`
- **Form id:** `1FAIpQLSc-ubmmEowkPO6XiQaafdj7XzOBLSZoMmvaCghQxx6ZaQV17g`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/ מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSc-ubmmEowkPO6XiQaafdj7XzOBLSZoMmvaCghQxx6ZaQV17g/analyticsrestricted). Good.

##  דרוש.ה מניקוריסט.ית

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSeMqH7pB2-_Ir06vvgsEEXfI2XdJAGV3POsKGAhA4KSQflf1g/viewform`
- **Form id:** `1FAIpQLSeMqH7pB2-_Ir06vvgsEEXfI2XdJAGV3POsKGAhA4KSQflf1g`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSeMqH7pB2-_Ir06vvgsEEXfI2XdJAGV3POsKGAhA4KSQflf1g/analyticsrestricted). Good.

## דרושים מצילי בריכה ומדריכי שחייה

- **Target:** `https://docs.google.com/forms/d/e/1FAIpQLSd0yF_w4WtmgdED41B3wey7-u1oLrdVg0C2QZvgGB2828IOrw/viewform`
- **Form id:** `1FAIpQLSd0yF_w4WtmgdED41B3wey7-u1oLrdVg0C2QZvgGB2828IOrw`
- **Overall risk:** **MEDIUM**

### Questions
| Required | Type | Question | PII |
|---|---|---|---|
| ✅ | short_answer | שם+ שם משפחה | full_name |
| ✅ | short_answer | מספר נייד | phone |
| ✅ | date | תאריך לידה | dob |
| ✅ | multiple_choice | אני מעוניין/מעוניינת להתמיין למשרת |  |

### Findings
#### `MEDIUM` — Collects phone number
Question(s): “מספר נייד”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `MEDIUM` — Collects date of birth
Question(s): “תאריך לידה”

> **Fix:** Confirm the linked responses Google Sheet is shared 'Restricted', set a data-retention/deletion routine, and verify a lawful basis for collecting this data.

#### `LOW` — Manually verify the linked responses Sheet
FormSentry cannot see the sharing settings of the Google Sheet that backs the responses — that is the most common real-world leak path.

> **Fix:** Open the responses Sheet → Share → confirm it is 'Restricted' (not 'Anyone with the link').

#### `INFO` — Response summary is restricted
The /viewanalytics endpoint is not public (HTTP 302 → https://docs.google.com/forms/d/e/1FAIpQLSd0yF_w4WtmgdED41B3wey7-u1oLrdVg0C2QZvgGB2828IOrw/analyticsrestricted). Good.

