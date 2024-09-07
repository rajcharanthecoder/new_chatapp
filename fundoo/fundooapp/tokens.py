from django.contrib.auth.tokens import PasswordResetTokenGenerator


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        # Replace six.text_type with str for Python 3.x
        return (str(user.pk) + str(timestamp) + str(user.is_active))


account_activation_token = AccountActivationTokenGenerator()
