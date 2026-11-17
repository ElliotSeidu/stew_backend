from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    """
    Standardizes error responses to match the frontend expectations:
    {
      "message": "...",
      "detail": "...",
      "errors": { "field": "..." },
      "code": "..."
    }
    """
    response = exception_handler(exc, context)

    if response is not None:
        data = response.data
        message = 'Something went wrong'
        errors = {}

        if isinstance(data, dict):
            if 'detail' in data:
                message = str(data['detail'])
            elif 'message' in data:
                message = str(data['message'])
            elif data:
                # Field errors
                errors = data
                first_key = next(iter(data))
                first_val = data[first_key]
                first_msg = first_val[0] if isinstance(first_val, list) and first_val else str(first_val)
                message = f"{first_key}: {first_msg}" if first_key != 'non_field_errors' else first_msg

            code = data.get('code', None)
        elif isinstance(data, list) and data:
            message = str(data[0])
            code = None
        else:
            message = str(data)
            code = None

        payload = {
            'message': message,
            'detail': message,
            'errors': errors or (data if isinstance(data, dict) and 'detail' not in data else {}),
        }
        if code:
            payload['code'] = code

        response.data = payload

    return response
