package twoauth.backend.security;

import twoauth.backend.security.model.AuthRequest;
import twoauth.backend.security.model.User;
import org.apache.commons.validator.routines.EmailValidator;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

public final class Validator
{
    private static final String INVALID_OT_ACTIVATION_TOKEN = "One Time Activation Token is invalid.";
    private static final Pattern EMAIL_CHARS_PATTERN;
    private static final Pattern NAME_CHARS_PATTERN;
    private static final Pattern MORE_THAN_ONE_SPACE_PATTERN;
    private static final Date MIN_DATE;

    static {
        EMAIL_CHARS_PATTERN = Pattern.compile("[a-z0-9._@-]*");
        NAME_CHARS_PATTERN = Pattern.compile("[A-Za-z ]*");
        MORE_THAN_ONE_SPACE_PATTERN = Pattern.compile("( )\\1");

        final LocalDate localDate = LocalDate.of(2024, 1, 1);
        MIN_DATE = Date.from(localDate.atStartOfDay(java.time.ZoneOffset.UTC).toInstant());
    }

    private Validator() {}

    public static String validateEmail(final String email) {
        if (email == null)
            return "Email is null.";

        if (email.isBlank())
            return "Email is blank.";

        if (email.length() < 6 || email.length() > 50)
            return "Email size is not in range (6,50) inclusive.";

        if (! EMAIL_CHARS_PATTERN.matcher(email).matches())
            return String.format("Email not matches %s pattern.", EMAIL_CHARS_PATTERN);

        if (! EmailValidator.getInstance(false, true).isValid(email))
            return "Not a valid email.";

        return null;
    }

    public static String validateName(final String name, final String prefix) {
        if (name == null)
            return String.format("%sName is null.", prefix);

        if (name.isBlank())
            return String.format("%sName is blank.", prefix);

        if (name.length() < 3 || name.length() > 40)
            return String.format("%sName size is not in range (3,40) inclusive.", prefix);

        if (! NAME_CHARS_PATTERN.matcher(name).matches())
            return String.format("%sName not matches %s pattern.", prefix, NAME_CHARS_PATTERN);

        // no SPACE at the start and end of the string
        if (! name.equals(name.trim()))
            return String.format("%sName has a SPACE at the start or at the end.", prefix);

        // no double or more repeated SPACE
        if (MORE_THAN_ONE_SPACE_PATTERN.matcher(name).matches())
            return String.format("%sName has double repeated SPACE chars.", prefix);

        return null;
    }

    public static String validateRegistrationDate(final Date date, final String prefix) {
        if (date == null)
            return String.format("%sDate is null.", prefix);

        if (date.after(new Date()))
            return String.format("%sDate is in the future.", prefix);

        if (date.before(MIN_DATE))
            return String.format("%sDate is before year 2024.", prefix);

        return null;
    }

    public static String validatePermissions(List<String> permissions) {
        if (permissions == null)
            return "Permissions are null.";

        if (permissions.isEmpty() || permissions.size() > 50) {
            return "Permissions size is not in range (1,50) inclusive.";
        }

        for (String p : permissions) {
            if (p == null)
                return "A permission is null.";

            if (p.isBlank())
                return "A permission is blank.";

            if (p.length() > 50)
                return "A permission size is not in range (1,50) inclusive.";
        }

        return null;
    }

    /* Minimum acceptable password: a2R_a2R_ */
    public static String validatePassword(final char[] password) {
        if (password == null)
            return "Password is null.";

        final int len = password.length;
        if (len < 8 || len > 120)
            return clearPassword(password, "Password is not in range (8,120) inclusive.");

        int upperCaseCount = 0;
        int digitCount = 0;
        int specialCount = 0;

        for (int i = 0; i < len; ++i) {
            if (Character.isDigit(password[i]))
                ++digitCount;
            else if (Character.isUpperCase(password[i]))
                ++upperCaseCount;
            else if (! Character.isLetterOrDigit(password[i]))
                ++specialCount;
        }

        int lowerCaseCount = len - (upperCaseCount + digitCount + specialCount);
        if (lowerCaseCount < 2)
            return clearPassword(password, "Password has less then 2 lower case letters.");

        if (upperCaseCount < 2)
            return clearPassword(password, "Password has less then 2 upper case letters.");

        if (digitCount < 2)
            return clearPassword(password, "Password has less then 2 digits.");

        if (specialCount < 2)
            return clearPassword(password, "Password has less then 2 special characters.");

        return clearPassword(password, null);
    }

    // Check if character is allowed in standard Base64
    private static boolean isBase64Char(char c) {
        return (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '+' || c == '/' || c == '=';
    }

    public static String validateBase64OTActivationToken(final String base64OTActivationToken) {
        if (base64OTActivationToken == null)
            return "One Time Activation Token is null.";

        // Must be multiple of 4
        if (base64OTActivationToken.length() > 128 || (base64OTActivationToken.length() % 4 != 0)) {
            return "One Time Activation Token has an incorrect size.";
        }

        if (base64OTActivationToken.isBlank())
            return "One Time Activation Token is blank.";

        // Fast manual character validation
        final int strSize = base64OTActivationToken.length();
        for (int i = 0; i < strSize; i++) {
            if (! isBase64Char(base64OTActivationToken.charAt(i)))
                return INVALID_OT_ACTIVATION_TOKEN;
        }

        try {
            Base64.getDecoder().decode(base64OTActivationToken);
        }
        catch (IllegalArgumentException e) {
            return INVALID_OT_ACTIVATION_TOKEN;
        }

        return null;
    }

    private static String clearPassword(char[] password, String errorMessage) {
        Arrays.fill(password, '\0');
        return errorMessage;
    }

    public static String validateUserRegistrationDto(User.RegistrationDto user) {
        if (user == null)
            return "User is null.";

        String errorMessage;
        if ((errorMessage = validateEmail(user.getEmail())) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.getFirstName(), "First")) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.getLastName(), "Last")) != null)
            return errorMessage;

        if ((errorMessage = validatePermissions(user.getPermissions())) != null)
            return errorMessage;

        if ((errorMessage = validatePassword(user.getPassword().toCharArray())) != null)
            return errorMessage;

        return null;
    }

    public static String validateUserSecureDto(User.SecureDto user) {
        if (user == null)
            return "User is null.";

        String errorMessage;
        if ((errorMessage = validateEmail(user.email())) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.firstName(), "First")) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.lastName(), "Last")) != null)
            return errorMessage;

        if ((errorMessage = validateRegistrationDate(user.creation(), "Creation")) != null)
            return errorMessage;

        if ((errorMessage = validateRegistrationDate(user.lastUpdate(), "LastUpdate")) != null)
            return errorMessage;

        if ((errorMessage = validatePermissions(user.permissions())) != null)
            return errorMessage;

        return null;
    }

    public static String validateUser(User user) {
        if (user == null)
            return "User is null.";

        String errorMessage;
        if ((errorMessage = validateEmail(user.getUsername())) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.getFirstName(), "First")) != null)
            return errorMessage;

        if ((errorMessage = validateName(user.getLastName(), "Last")) != null)
            return errorMessage;

        if ((errorMessage = validateRegistrationDate(user.getCreation(), "Creation")) != null)
            return errorMessage;

        if ((errorMessage = validateRegistrationDate(user.getLastUpdate(), "LastUpdate")) != null)
            return errorMessage;

        var authorities = user.getAuthorities();
        if (authorities == null)
            return "Permissions are null.";

        if ((errorMessage = validatePermissions(user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList())) != null)
            return errorMessage;

        if (user.isActive() && user.getActivationToken() != null) {
            return "Enable Token is not null, but the account is already enabled.";
        }
        else if (! user.isActive() && user.getActivationToken() == null) {
            return "Enable Token is null, but the account is not enabled.";
        }

        if ((errorMessage = validatePassword(user.getPassword().toCharArray())) != null)
            return errorMessage;

        return null;
    }

    public static String validateAuthRequest(AuthRequest request) {
        if (request == null)
            return "Authentication Request is null.";

        String errorMessage;
        if ((errorMessage = validateEmail(request.getEmail())) != null)
            return errorMessage;

        if ((errorMessage = validatePassword(request.getPassword().toCharArray())) != null)
            return errorMessage;

        String oneTimeActivationToken;
        if ((oneTimeActivationToken = request.getBase64OTActivationToken()) != null
            && (errorMessage = validateBase64OTActivationToken(oneTimeActivationToken)) != null)
                return errorMessage;

        return null;
    }
}
