rule fake_html_login_phish
{

  meta:
  
    author = "0x3ronic"
    info = "Obfuscated JS file containing fake MS sign-in page connecting to malicous URL"
  
  strings:
    
    $a1 = "document.write(unescape("
    $a2 = "%0a%3c%68%74%6d%6c%20%64%69%72%3d%22%6c%74"
    $a3 = "8%2c%20%69%6e%69"
    
  condition:
  
    all of them
    
}
