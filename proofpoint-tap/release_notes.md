#### What's Fixed
- Updated the Get Blocked Malicious URL Events, Get Permitted Malicious URL Events, Get Blocked Threat Message Events, Get Delivered Threat Message Events, Get All Events, Get Events as follows:
    - "Interval" param is available as documented in Proofpoint API to focus on a specific interval defined as a string containing an ISO8601-formatted interval.
      - 2026-03-23T12:00:00Z/2026-03-23T13:00:00Z - an hour interval, beginning at noon UTC on 03-23-2026
      - PT30M/2026-03-23T12:30:00Z - the thirty minutes beginning at noon UTC on 25-03-2026 and ending at 12:30pm UTC
      - 2026-03-23T05:00:00-0700/PT30M - the same interval as above, but using -0700 as the time zone
- Added Data Ingestion Playbook to fetch "Messages Blocked" or "Clicks Permitted". If no Data sample available in the past 3600 seconds then a mock output is provided as sample.
