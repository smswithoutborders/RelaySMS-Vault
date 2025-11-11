# **API V3 Resource Documentation**

## **Base URL**

```
https://vault.smswithoutborders.com
```

## **Endpoints**

### **1. Get Static x25519 Public Keys**

Retrieve static x25519 public keys from the system.

#### **Endpoint**

```
GET /v3/keys/static-x25519
```

#### **Response**

**Status Code: 200 OK**

**Response Body:**

> The status can be `active`, `inactive`, or `archived`.

```json
{
  "v1": [
    {
      "keypair": "pqkZPzH6jqZN5n45RuY91+k5ESxijfYOR+caOALJe1I=",
      "kid": 0,
      "status": "active"
    },
    {
      "keypair": "gh7eH6GT5l+wXnz0z/nqMu/BhSlyz7FxqFoneaPbS3E=",
      "kid": 1,
      "status": "active"
    }
  ],
  "v2": [
    {
      "keypair": "NJuBTMkQzLors6ZCok+ZBDWOXSB1NDhjKGKGchd1q1k=",
      "kid": 0,
      "status": "active"
    },
    {
      "keypair": "TdKzENsuN6LHlf6XalCEeE32lstF3KoVy1xi443WDAg=",
      "kid": 1,
      "status": "active"
    }
  ]
}
```

**Status Code: 500 Internal Server Error**

**Response Body:**

```json
{
  "error": "Oops! Something went wrong. Please try again later."
}
```

---

### **2. Get Signup Metrics**

Retrieve metrics for user signups within a specified date range, with options for filtering and pagination.

#### **Endpoint**

```
GET /v3/metrics/signup
```

#### **Query Parameters**

| Parameter      | Type   | Required | Description                                                                          |
| -------------- | ------ | -------- | ------------------------------------------------------------------------------------ |
| `start_date`   | string | Yes      | Start date in "YYYY-MM-DD" format.                                                   |
| `end_date`     | string | Yes      | End date in "YYYY-MM-DD" format.                                                     |
| `country_code` | string | No       | Country code for filtering signup users.                                             |
| `granularity`  | string | No       | Granularity for date grouping: "day" or "month". Defaults to "day".                  |
| `group_by`     | string | No       | Grouping option: "country", "date", or None. Defaults to None (returns total count). |
| `top`          | int    | No       | Limits the number of results returned (overrides `page` and `page_size`).            |
| `page`         | int    | No       | Page number for pagination. Defaults to `1`.                                         |
| `page_size`    | int    | No       | Number of records per page. Defaults to `50`. Maximum recommended value is `100`.    |

#### **Response**

**Status Code: 200 OK**

**Response Body:**

```json
{
  "total_countries": 10,
  "total_signup_users": 120,
  "total_countries": 2,
  "total_signups_from_bridges": 3,
  "total_signup_users_with_emails": 45,
  "countries": [
    "CM",
    "NG"
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_pages": 3,
    "total_records": 120
  },
  "data": [
    {
      "country_code": "CM",
      "signup_users": 30
    },
    {
      "timeframe": "2024-12-01",
      "signup_users": 20
    },
    ...
  ]
}
```

**Status Code: 400 Bad Request**

**Response Body (Examples):**

- Missing required parameters:

  ```json
  {
    "error": "Invalid input parameters. Provide 'start_date' and 'end_date'."
  }
  ```

- Invalid `page`, `page_size`, or conflicting parameters (e.g., `top` with pagination):

  ```json
  {
    "error": "'top' cannot be used with 'page' or 'page_size'."
  }
  ```

- Invalid `granularity` value:

  ```json
  {
    "error": "Invalid granularity. Use 'day' or 'month'."
  }
  ```

- Invalid `group_by` value:

  ```json
  {
    "error": "Invalid group_by value. Use 'country', 'date', or None."
  }
  ```

---

### **3. Get Retained User Metrics**

Retrieve metrics for retained (active) users within a specified date range, with options for filtering and pagination.

#### **Endpoint**

```
GET /v3/metrics/retained
```

#### **Query Parameters**

| Parameter      | Type   | Required | Description                                                                          |
| -------------- | ------ | -------- | ------------------------------------------------------------------------------------ |
| `start_date`   | string | Yes      | Start date in "YYYY-MM-DD" format.                                                   |
| `end_date`     | string | Yes      | End date in "YYYY-MM-DD" format.                                                     |
| `country_code` | string | No       | Country code for filtering retained users.                                           |
| `granularity`  | string | No       | Granularity for date grouping: "day" or "month". Defaults to "day".                  |
| `group_by`     | string | No       | Grouping option: "country", "date", or None. Defaults to None (returns total count). |
| `top`          | int    | No       | Limits the number of results returned (overrides `page` and `page_size`).            |
| `page`         | int    | No       | Page number for pagination. Defaults to `1`.                                         |
| `page_size`    | int    | No       | Number of records per page. Defaults to `50`. Maximum recommended value is `100`.    |

#### **Response**

**Status Code: 200 OK**

**Response Body:**

```json
{
  "total_countries": 10,
  "total_retained_users": 75,
  "total_retained_users_with_tokens": 70,
  "total_retained_users_with_emails": 30,
  "total_countries": 2,
  "countries": [
    "CM",
    "NG"
  ],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "total_pages": 3,
    "total_records": 75
  },
  "data": [
    {
      "country_code": "CM",
      "retained_users": 25
    },
    {
      "timeframe": "2024-12-01",
      "retained_users": 15
    },
    ...
  ]
}
```

**Status Code: 400 Bad Request**

**Response Body (Examples):**

- Missing required parameters:

  ```json
  {
    "error": "Invalid input parameters. Provide 'start_date' and 'end_date'."
  }
  ```

- Invalid `page`, `page_size`, or conflicting parameters (e.g., `top` with pagination):

  ```json
  {
    "error": "'top' cannot be used with 'page' or 'page_size'."
  }
  ```

  - Invalid `granularity` value:

  ```json
  {
    "error": "Invalid granularity. Use 'day' or 'month'."
  }
  ```

- Invalid `group_by` value:

  ```json
  {
    "error": "Invalid group_by value. Use 'country', 'date', or None."
  }
  ```
