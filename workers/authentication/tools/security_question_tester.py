"""Security question testing tool."""

from workers.authentication.base_tool import AuthenticationTool
from workers.authentication.concurrency import WeightClass


class SecurityQuestionTester(AuthenticationTool):
    """Test security question mechanisms (WSTG-ATHN-008)."""

    name = "security_question_tester"
    weight_class = WeightClass.HEAVY

    def build_command(self, target, credentials=None):
        target_value = getattr(target, 'target_value', str(target))
        base_url = target_value if target_value.startswith(('http://', 'https://')) else f"https://{target_value}"

        script = f'''
import httpx
import json
import re
from urllib.parse import urljoin

results = []
base_url = "{base_url}"

def safe_get(url, **kwargs):
    try:
        return httpx.get(url, follow_redirects=True, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

def safe_post(url, **kwargs):
    try:
        return httpx.post(url, follow_redirects=False, timeout=10, verify=False, **kwargs)
    except Exception:
        return None

# Common security questions and their typical answers
COMMON_QUESTIONS_AND_ANSWERS = {{
    "What is your mother's maiden name?": ["smith", "jones", "williams", "brown", "johnson"],
    "What was your first pet's name?": ["max", "buddy", "rocky", "sam", "bear"],
    "What is your favorite color?": ["blue", "red", "green", "black", "white"],
    "What city were you born in?": ["london", "new york", "paris", "chicago", "los angeles"],
    "What is your favorite movie?": ["star wars", "titanic", "avatar", "matrix", "godfather"],
    "What was your first car?": ["ford", "honda", "toyota", "bmw", "chevrolet"],
    "What is your favorite food?": ["pizza", "sushi", "burger", "pasta", "tacos"],
    "What school did you attend?": ["high school", "university", "college", "academy"],
    "What is your favorite sports team?": ["yankees", "lakers", "manchester united", "barcelona", "real madrid"],
    "What was your childhood nickname?": ["buddy", "champ", "ace", "kid", "junior"],
}}

# Weak questions that are easily guessable or discoverable
WEAK_QUESTION_PATTERNS = [
    r'mother.*maiden',
    r'birth.*city|born.*city|city.*born',
    r'first.*pet|pet.*name',
    r'favorite.*color',
    r'favorite.*movie',
    r'first.*car|car.*first',
    r'favorite.*food',
    r'school.*attend|attend.*school',
    r'favorite.*team|sports.*team',
    r'nickname',
    r'spouse.*name|partner.*name',
    r'anniversary',
]

# Discover forgot password / security question pages
forgot_password_urls = []
for path in [
    "/forgot-password", "/forgot_password", "/password/forgot",
    "/reset-password", "/reset_password", "/password/reset",
    "/recover", "/account/recover", "/password/recover",
    "/forgot-username", "/forgot_username",
    "/security-questions", "/security_questions",
    "/account/security", "/profile/security",
]:
    url = urljoin(base_url, path)
    r = safe_get(url)
    if r and r.status_code == 200:
        if re.search(r'<form[^>]*>', r.text, re.IGNORECASE):
            forgot_password_urls.append(url)

# Test 1: Enumerate security questions via forgot password flow
for fp_url in forgot_password_urls:
    r = safe_get(fp_url)
    if not r or r.status_code != 200:
        continue
    
    html = r.text
    
    # Look for security question fields
    question_selects = re.findall(r'<select[^>]*name=["\\'](?:security[_-]?question|question)[^>]*>(.*?)</select>', html, re.IGNORECASE | re.DOTALL)
    question_inputs = re.findall(r'<input[^>]*name=["\\'](?:security[_-]?question|question)[^>]*>', html, re.IGNORECASE)
    
    # Extract available questions from select options
    available_questions = []
    for select_content in question_selects:
        options = re.findall(r'<option[^>]*value=["\\']([^"\\']*)["\\']>([^<]+)</option>', select_content, re.IGNORECASE)
        for value, text in options:
            if value and text.strip():
                available_questions.append({{"value": value, "text": text.strip()}})
    
    if available_questions:
        # Check for weak questions
        weak_questions = []
        for q in available_questions:
            question_text = q["text"].lower()
            for pattern in WEAK_QUESTION_PATTERNS:
                if re.search(pattern, question_text):
                    weak_questions.append(q)
                    break
        
        if weak_questions:
            results.append({{
                "title": f"{{len(weak_questions)}} weak security questions available",
                "description": f"Found {{len(weak_questions)}} weak/easily guessable security questions on {{fp_url}}. These can be researched or brute-forced.",
                "severity": "medium",
                "data": {{
                    "weak_questions": [q["text"] for q in weak_questions],
                    "total_questions": len(available_questions),
                    "page": fp_url
                }}
            }})
        else:
            results.append({{
                "title": "Security questions found - reviewing strength",
                "description": f"Found {{len(available_questions)}} security questions on {{fp_url}}",
                "severity": "info",
                "data": {{
                    "questions": [q["text"] for q in available_questions],
                    "page": fp_url
                }}
            }})

# Test 2: Test if answers are case-sensitive
if available_questions and forgot_password_urls:
    fp_url = forgot_password_urls[0]
    r = safe_get(fp_url)
    if r:
        html = r.text
        
        # Find form action
        form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
        action_url = urljoin(fp_url, form_action.group(1)) if form_action else fp_url
        
        # Find username/email field
        username_field = "username"
        email_field = "email"
        username_match = re.search(r'<input[^>]*name=["\\']([^"\\']*(?:username|email|login)[^"\\']*)["\\']', html, re.IGNORECASE)
        if username_match:
            if "email" in username_match.group(1).lower():
                email_field = username_match.group(1)
            else:
                username_field = username_match.group(1)
        
        # Find answer field
        answer_field = "answer"
        answer_match = re.search(r'<input[^>]*name=["\\']([^"\\']*(?:answer|response)[^"\\']*)["\\']', html, re.IGNORECASE)
        if answer_match:
            answer_field = answer_match.group(1)
        
        # Find question field
        question_field = "question"
        question_match = re.search(r'<(?:select|input)[^>]*name=["\\']([^"\\']*(?:question)[^"\\']*)["\\']', html, re.IGNORECASE)
        if question_match:
            question_field = question_match.group(1)
        
        # Test case sensitivity with a known question/answer
        test_question = available_questions[0]["value"] if available_questions else "1"
        
        # Try lowercase answer
        form_data_lower = {{
            username_field: "test@test.com",
            question_field: test_question,
            answer_field: "testanswer",
        }}
        r_lower = safe_post(action_url, data=form_data_lower)
        
        # Try uppercase answer
        form_data_upper = {{
            username_field: "test@test.com",
            question_field: test_question,
            answer_field: "TESTANSWER",
        }}
        r_upper = safe_post(action_url, data=form_data_upper)
        
        # Compare responses
        if r_lower and r_upper:
            if r_lower.text == r_upper.text and r_lower.status_code == r_upper.status_code:
                results.append({{
                    "title": "Security question answers may not be case-sensitive",
                    "description": "Responses for lowercase and uppercase answers appear identical, suggesting case-insensitive comparison.",
                    "severity": "low",
                    "data": {{
                        "lower_status": r_lower.status_code,
                        "upper_status": r_upper.status_code,
                        "responses_identical": True
                    }}
                }})

# Test 3: Test for answer brute-forcing capability
# Check if there's rate limiting on the security question endpoint
for fp_url in forgot_password_urls:
    r = safe_get(fp_url)
    if not r:
        continue
    
    html = r.text
    form_action = re.search(r'<form[^>]*action=["\\']([^"\\']*)["\\']', html, re.IGNORECASE)
    action_url = urljoin(fp_url, form_action.group(1)) if form_action else fp_url
    
    # Try multiple answers quickly
    answers_tried = 0
    rate_limited = False
    
    for i in range(10):
        form_data = {{
            "username": "test@test.com",
            "question": "1",
            "answer": f"guess{{i}}",
        }}
        r = safe_post(action_url, data=form_data)
        if r:
            answers_tried += 1
            if r.status_code == 429:
                rate_limited = True
                break
            if "too many" in r.text.lower() or "rate limit" in r.text.lower():
                rate_limited = True
                break
    
    if not rate_limited and answers_tried == 10:
        results.append({{
            "title": "Security question answers can be brute-forced",
            "description": f"No rate limiting detected on security question endpoint. Successfully submitted {{answers_tried}} answers without throttling.",
            "severity": "high",
            "data": {{
                "page": fp_url,
                "answers_submitted": answers_tried,
                "rate_limiting": False
            }}
        }})
    elif rate_limited:
        results.append({{
            "title": "Rate limiting on security question answers",
            "description": f"Rate limiting detected after {{answers_tried}} attempts on security question endpoint.",
            "severity": "info",
            "data": {{
                "page": fp_url,
                "attempts_before_limit": answers_tried
            }}
        }})

# Test 4: Test for security question bypass
for fp_url in forgot_password_urls:
    # Try accessing password reset without answering security questions
    bypass_paths = [
        "/reset-password",
        "/password/reset",
        "/account/reset",
        "/forgot-password/skip",
        "/forgot-password/bypass",
    ]
    
    for bypass_path in bypass_paths:
        url = urljoin(base_url, bypass_path)
        r = safe_get(url)
        if r and r.status_code == 200:
            if re.search(r'(?:password|new[_-]?password|confirm[_-]?password)', r.text, re.IGNORECASE):
                results.append({{
                    "title": f"Potential security question bypass: {{bypass_path}}",
                    "description": f"Password reset form accessible at {{bypass_path}} without going through security questions.",
                    "severity": "high",
                    "data": {{
                        "bypass_url": url,
                        "original_forgot_url": fp_url
                    }}
                }})

# Test 5: Check if security questions can be enumerated via API
api_paths = [
    "/api/security-questions",
    "/api/v1/security-questions",
    "/api/v2/security-questions",
    "/api/user/security-questions",
    "/api/account/security-questions",
    "/api/questions",
]

for api_path in api_paths:
    url = urljoin(base_url, api_path)
    r = safe_get(url)
    if r and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) or (isinstance(data, dict) and "questions" in data):
                results.append({{
                    "title": f"Security questions exposed via API: {{api_path}}",
                    "description": f"Security questions are enumerable via unauthenticated API endpoint {{api_path}}",
                    "severity": "high",
                    "data": {{
                        "api_url": url,
                        "response_type": type(data).__name__,
                        "question_count": len(data) if isinstance(data, list) else len(data.get("questions", []))
                    }}
                }})
        except Exception:
            pass

# Summary
if not results:
    results.append({{
        "title": "Security question test completed",
        "description": "No security question endpoints found or all checks passed",
        "severity": "info",
        "data": {{
            "forgot_password_urls_checked": len(forgot_password_urls),
            "api_paths_checked": len(api_paths)
        }}
    }})

print(json.dumps(results))
'''
        return ["python3", "-c", script]

    def parse_output(self, stdout):
        import json
        try:
            return json.loads(stdout.strip())
        except (json.JSONDecodeError, ValueError):
            return []
