# Mijn.Host-testomgeving zonder Desktop Commander

De bestaande `myhost-mailbox`-runtime wordt automatisch getest op Linux en Windows.
Een echte **afgeschermde Dovecot-container** wordt gebruikt voor IMAPS (TLS),
authenticatie, aanmaken, teruglezen, vervangen en gericht verwijderen van
uitsluitend fictieve conceptmails. De Docker-container wordt na iedere run gewist.
Geen SMTP, Mijn.Host-wachtwoorden, leads of echte berichten zijn betrokken.

De workflow heeft twee afzonderlijke testniveaus:

1. **Automatisch bij elke PR/push**: bestaande unit-tests en een echte IMAPS-test
   op een tijdelijke Dovecot-mailserver. Ook draaien de Python-tests op een
   echte GitHub-gehoste Windows-runner. Geen desktopverbinding vereist.
2. **Op expliciet verzoek V11 op Windows**: plaats één gecontroleerde V11-ZIP
   als releasebestand in *deze repository*, kies Actions ->
   "Isolated mailbox end-to-end" -> Run workflow. Vul de volledige
   GitHub-release-URL en de SHA256 van exact dat ZIP-bestand in.
   De workflow controleert de hash en voert de bijgeleverde V11-tests uit,
   inclusief echte Windows-DPAPI en Credential Manager, met een tijdelijke
   fictieve gebruikersnaam in de Windows Credential Manager.

De ZIP-check weigert nu ontbrekende programmabestanden, onjuiste of ontbrekende
`SHA256SUMS.txt`-regels, dubbele ZIP-bestanden, een verkeerde downloadhash,
en een testsuite met minder dan 190 tests of overgeslagen scenario's.
De hash is alleen betrouwbaar wanneer hij onafhankelijk van de release-ZIP
is vastgesteld. Een groene protocoltest is **geen** Windows-V11-goedkeuring.

**Een sandbox-link van ChatGPT is geen publiek GitHub-releasebestand.** De
conversatie-ZIP moet dus eenmalig als release-asset aan deze repository worden
gekoppeld voordat de V11-Windows-test op GitHub zelf kan draaien. Een GitHub
Actions-succes van niveau 1 betekent niet dat V11 getest is.

## Grenzen

- De synthetische Dovecot-test bewijst de protocolroute van **myhost-mailbox**;
  de losse Windows-V11-tool heeft eigen broncode en eigen tests.
- De V11-release-actie test de eigen unit/GUI-tests en native Windows-beveiliging;
  een volledig geautomatiseerde V11-GUI-klikroute tegen een echte IMAPS-server
  vereist een aparte integratie van de V11-broncode. Deze workflow pretendeert
  dat niet.
- Niet alle hosted Windows-runners bieden een interactieve desktop voor Tk.
  Een GUI-test die hierdoor faalt is een echte blokkade, geen reden om tests
  stil uit te schakelen.
- Geen van beide tests bevestigt het gedrag van de **productie**-Mijn.Host-server
  of de echte mailbox. Daarvoor blijven twee afzonderlijke proefconcepten en
  handmatige verificatie van back-up en herstel noodzakelijk.
- Gebruik alleen de fictieve `ci-fake@example.invalid`-account in de teststraat.
  De code weigert bewust andere IMAP-parameters.

## Technische referenties

- Dovecot: https://doc.dovecot.org/2.4.4/installation/docker.html
- GreenMail: https://greenmail-mail-test.github.io/greenmail/
- Python `imaplib`: https://docs.python.org/3/library/imaplib.html
- GitHub Actions Windows: https://docs.github.com/en/actions
- GitHub workflow artifacts: https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts