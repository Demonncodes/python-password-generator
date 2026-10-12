
import string
import secrets

def generate_password(length, use_upper, use_lower,
                      use_digits, use_symbols):
    characters = ""

    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += "!@#$%^&*()-_=+"

    if not characters:
        return None

    # Guarantee at least one character from each selected category
    groups = []
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append("!@#$%^&*()-_=+")

    if length < len(groups):
        return None

    password_chars = [secrets.choice(group) for group in groups]

    password_chars.extend(
        secrets.choice(characters)
        for _ in range(length - len(password_chars))
    )

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def check_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+" for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    return "Strong"


def main():
    print("=" * 35)
    print("     PASSWORD GENERATOR 2.0")
    print("=" * 35)

    try:
        length = int(input("Password length: "))
        count = int(input("Number of passwords: "))

        if length < 1 or count < 1:
            print("Length and count must be positive!")
            return

        upper = input("Include uppercase? (y/n): ").lower() == "y"
        lower = input("Include lowercase? (y/n): ").lower() == "y"
        digits = input("Include numbers? (y/n): ").lower() == "y"
        symbols = input("Include symbols? (y/n): ").lower() == "y"

        print("\n" + "=" * 35)

        for i in range(count):
            password = generate_password(
                length, upper, lower, digits, symbols
            )

            if password is None:
                print("Error: Select at least one category,")
                print("and length must cover all selected categories.")
                return

            print(f"Password {i + 1}: {password}")
            print(f"Strength: {check_strength(password)}")
            print("-" * 35)

    except ValueError:
        print("Please enter valid numbers!")


if __name__ == "__main__":
    main()
