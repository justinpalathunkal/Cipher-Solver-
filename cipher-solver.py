import numpy as np

class Cipher(object):
  def __init__(self, cipher_text, key_len):
    self.cipher_text = cipher_text # provided cipher text to be decrypted
    self.chunk_text = ["","","","","",""] # list of chunked list of size 6 (key length is 6)
    self.key_len = key_len # provided length of secret key
 
  def convert_letter_to_num(self, letter):
    # converting a character to it's unicode, then subtracting by 97 so 'a' = 0, 'b' = 1, etc.
    return ord(letter) - 97

  def convert_num_to_letter(self, num):
    # converting a unicode to it's character by adding 97, since we consider 'a' = 0, 'b' = 1, etc.
    return chr(num + 97)

  def generate_letter_dict(self):
    # initialize a dictionary for keeping count of the # of occurrences of each letter
    dict = {}
    # string of all possible lower-case letters
    char_possibilities = "abcdefghijklmnopqrstuvwxyz"
    # initialize each letter (key) to a value of 0
    for letter in char_possibilities:
      dict[letter] = 0
    return dict

  # 1A
  def count_letter_occurrence(self, text):
    letter_dict = self.generate_letter_dict()
    for letter in text:
      #counts number of occurrences of each letter in ciphertext
      letter_dict[letter] += 1
    return letter_dict

  # 2A
  def generate_chunk_text(self, text, key_len):
    for i in range(len(text)):
      # separates the ciphertext into chunks
      self.chunk_text[i % key_len] += text[i]

  # 3
  def find_secret_key(self):
    # for each chunk
    secret_key = ""
    for chunk in self.chunk_text:
      chunk_dict = self.count_letter_occurrence(chunk)
      chunk_counts = list(chunk_dict.values())
      # checks chunk frequency analysis and returns letter that occurs the most
      max_index = np.argmax(chunk_counts)

      # references the letter that occurs the most with respect to 'e' to get the offset used for that key character
      if max_index < 4:
        secret_key += self.convert_num_to_letter(26-max_index)
      else:
        secret_key += self.convert_num_to_letter(max_index-4)
    return secret_key
 
  # 4
  def decrypt_cipher_text(self, secret_key):
    plain_text = ""
    for i in range(len(self.cipher_text)):
      # convert the letter into a number
      cipher_num = self.convert_letter_to_num(self.cipher_text[i])

      # gets offset from the secret key
      offset = self.convert_letter_to_num(secret_key[i % self.key_len])

      # shifts ciphertext letter based on the secret key
      if cipher_num - offset < 0:
        # if adding the offset is below zero, wrap around to the end of the alphabet
        plain_text += self.convert_num_to_letter(26 + cipher_num - offset )
      else:
        plain_text += self.convert_num_to_letter(cipher_num - offset)
    return plain_text

  def decrypt(self):
    # full cipher text letter occurrence
    full_cipher_dict = self.count_letter_occurrence(self.cipher_text)
    print("1A - Ciphertext # of Occurrences:", list(full_cipher_dict.values()))
    print("\n")
    # chunks the text
    self.generate_chunk_text(self.cipher_text, self.key_len)
    print("2A - Chunked Text:", self.chunk_text)  
    print("\n")
    # find the secret key knowing key length is 6
    secret_key = self.find_secret_key()
    print("3 - Secret Key:", secret_key)
    print("\n")
    # decrypt the cipher text to plaintext using the secret key
    plain_text = self.decrypt_cipher_text(secret_key)
    print("4 - Plaintext:", plain_text)
    print("\n")

def main():
  # provided ciphertext to be decrypted
  cipher_text = "agpygmqgxyxfiuimypmvcmssvuiyjcggxripiuxyjrlkwdivxkwtyqxtexhmquxejdjtswxfikrdiprgxdlcgqpyvmjcrsqypumcfwrqqoelwcqkxritspgfepgomrhgtorbwqrwelcesxwghgvkxgspwlyrmpxrikelsbmrcqjmeqiuxorbwvszvmxggdxficrsqyphvyqbepkovzctixhcvkrqmrpgwcgmrutsgsswwziplctcmrqccliqekhdlyxkjmsjstmxkgwoesrjcrvyxcgvmfirlgvosskjxdszidydjcadvskfxncmsjstinelmoevwrlgvoepijsgititryxyjgameqiumxafmelfmtmfgypmvuebirlgqcijzgwzvmxggdmtivloogrijswfitmdwcphxrsskjwyfpmildpwgqpyvchkwlclsoikrqicwixmwgidlcfnyolyvosxmxiuasxfxjigeritexhrlgfsvbeumdhyvvwkpmrixriqxtikqjsqocejqqwdpgogeppywjspwsrnmqlrhgwovrepmwejwcvokcrgvkpjcvlogmpqvyjrlghowcvvxryqjqvsrqxcrmirlgpsslxjikrrinsziyrfxriumnhnslogckvcenpcelhesvspifmxhcifwkcqgcryrrvkwdvyqkrdlchgwovrajibilikxripxtiowzvwwramsfryvczgrerbynedmmrqjdlcwwvpeaicjpsphvlowjmildiqxrvyxcgvmyrrskxcjmiuewsbmhmmermqryjasnsbeqwkqspyxghdsrlcxyjrlgwevpswrnmlkeserrvamcezwqpexcparogcwuebcfipgoagxjsexcbeizxgspxristribtjyoeqimjgzovwfkvnelhcpcsrlgjevmjcpvxfiuqkpjitqkqkenwkrbxjicogrqjkpjxjicryogwkrbpkdkvbwkwyjmrgyxmdstqcelhesvspxjixivxrssrrmuxriasnsbsdxjiwerytimerittspjetwcskiqjglggjebizvqaxxfmutbszedpiqyogwdlcgcxovnmnpkvczgrwspiesxwnmeyyyqeosxkrlgkbicrnikzcwvlkruswpnsrlgvgmqididlcgcwopcxwwcicxjixafivlovrlglkfgxuspxfikrciaxymvprltsgelcnmqlryrsxxfitmnhjiylkxuswpncmyfssjwswaovcedmqgyxgvzmjpcvglwpkooqmwvsdlcvfipilwgpowqgtikxsvgwissaqyvhdighlclmildelhnmogmreikpchdcnewwqhyxfiuimerittspjetwglcrvloqmvpmxkjmildgmqgwdlccevoinhqaxxfiuxoqmjvlojmsftvelxcrnpgiesxgceninekspkdlcxjmmofitfkkcephnvwwvmmoqephviyzgwxiyvvlokpswrnelhkxswmfxmyyqxjedylhgvcyalembgsquxkraiuxrizvqaxgmpqvbiypncliasoicenvqxogrmqrsxkmildmlhginfcetkeibxjedxfieediptkpvepwjefmlkdimskidvyalgqrmiypghdlcquivzcwqrdlcktserbephdlyxyigipitifipwkrqxfiuxkxcshxrmlkufexrlkwswlsvwyfcgcyciulkpoacqccceweueqilitevvspgxrerpcvqiaevibtgpnebwdighlclmildelhnmogmreikpchdcnewmvmcfwrqqoelwcpgewwvlogywgxrerxjiiepidvyalwqqosdxjiwwrmnpbirekrsrexjiqvcipgypmvyiwewxjixgmrepehcxjedxfijelmrshgyraicpsrexjiwwcpxicfwhccmekihmbwrephdlyxvlofpsyrmsjstmcejevibeberxkxgsp"
  # provided secret key length of 6
  key_len = 6
  cipher = Cipher(cipher_text, key_len)
  cipher.decrypt()

if __name__ == "__main__":
  main()
