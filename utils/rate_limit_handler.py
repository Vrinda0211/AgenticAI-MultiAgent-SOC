
import time
import re

def call_with_retry(agent, messages, max_retries=3):
    for attempt in range(max_retries):
        try:
            return agent.invoke(messages)
        
        except Exception as e:
            error_str = str(e)
            
            if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                
                wait_match = re.search(r'retry in (\d+\.?\d*)s', error_str, re.IGNORECASE)
                if wait_match:
                    wait_time = float(wait_match.group(1)) + 5  
                else:
                    wait_time = 60 * (attempt + 1) 

                if "PerDay" in error_str or "per_day" in error_str.lower():
                    print(f"   DAILY LIMIT EXHAUSTED")
                    print(f"   You have used all requests for today.")
                    print(f"   Quota resets at midnight Pacific Time (5:30 AM IST)")
                    print(f"   Nothing to do but wait until tomorrow.")
                    raise Exception("Daily quota exhausted — try again after 5:30 AM IST") from e

                elif "PerMinute" in error_str or "per_minute" in error_str.lower():
                    print(f"  PER-MINUTE LIMIT HIT (attempt {attempt+1}/{max_retries})")
                    print(f"   Waiting {wait_time:.0f} seconds before retrying...")
                    time.sleep(wait_time)
                    print(f"   Retrying now...")

                else:
                    print(f"  RATE LIMIT HIT — unknown type (attempt {attempt+1}/{max_retries})")
                    print(f"   Waiting {wait_time:.0f}s...")
                    time.sleep(wait_time)

            else:
                raise e

    raise Exception(f"Max retries ({max_retries}) exceeded — still hitting rate limits")