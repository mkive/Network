import base64

encoded_string = 'G4JWIGURCV2G65DBNQQDIMCLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4.DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTEIBOBIZDMMRRGQ2D.CIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE.3SAMJTHIYDMIBOFYFDENRT'

# Remove dots (.)
encoded_string = encoded_string.replace('.', '')

# Add necessary padding
padding = '=' * ((8 - len(encoded_string) % 8) % 8)
padded_encoded_string = encoded_string + padding

# Decode
decoded_bytes = base64.b32decode(padded_encoded_string)

print(decoded_bytes)
