def detectUser(user):
    if user.role == 1:
        return 'vendorDashboard'  # Return the URL name for vendors
    elif user.role == 2:
        return 'customerDashboard'  # Return the URL name for customers
    elif user.role is None and user.is_superadmin:
        return 'admin:index'  # Use Django's default admin URL namespace
    else:
        return 'login'  # Fallback case if none of the above matches
