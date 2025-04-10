def check_email_allowed(backend, details, response, *args, **kwargs):
    email = details.get('email')
    if not email:
        raise AuthForbidden(backend)
    
    # Add any additional checks here
    return {'details': details}