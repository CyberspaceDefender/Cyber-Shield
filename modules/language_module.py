"""
Cyber-Shield Language Module
Generates security warnings and explanations in Nigerian local languages.
Uses template-based generation (offline-capable) with LLM-style personalisation.
"""

from typing import Optional


# ── Language definitions ──────────────────────────────────────────────────

LANGUAGES = {
    "pidgin": {"name": "Naija Pidgin", "code": "pc", "flag": "🇳🇬"},
    "yoruba": {"name": "Yorùbá",       "code": "yo", "flag": "🟢"},
    "hausa":  {"name": "Hausa",        "code": "ha", "flag": "🟡"},
    "igbo":   {"name": "Igbo",         "code": "ig", "flag": "🔵"},
    "english":{"name": "English",      "code": "en", "flag": "🇬🇧"},
}

# ── Warning templates by verdict × language ───────────────────────────────

TEMPLATES = {

    # ── SCAM ──────────────────────────────────────────────────────────────
    "SCAM": {
        "pidgin": {
            "headline": "⚠️ SCAM ALERT! Dis message na FRAUD!",
            "summary": "Abeg no click any link or send any money. Dis na scam wey dem dey use to steal your money and data.",
            "what_to_do": [
                "🚫 No click any link inside di message",
                "🚫 No share your OTP, PIN, or password with anybody",
                "🚫 No send money to anybody wey you no sabi",
                "✅ Delete di message and block di number",
                "✅ Report am to EFCC or your bank",
            ],
            "learn": "Scammers dey always create URGENCY — dem go say 'do am now or your account go close.' Real banks and government no dey work like that.",
        },
        "yoruba": {
            "headline": "⚠️ ÌKÌLỌ̀ AJẸGBÉ! Ìfọ̀rọ̀wánilẹ̀nuwò yìí jẹ́ JÍJẸ́BÉ!",
            "summary": "Jọ̀ọ́ má tẹ ìsopọ̀ kankan tàbí fi owó ránṣẹ́. Èyí jẹ́ ajẹgbé tó fẹ́ jí owó àti àlàyé rẹ.",
            "what_to_do": [
                "🚫 Má tẹ ìsopọ̀ kankan nínú ìfọ̀rọ̀wánilẹ̀nuwò náà",
                "🚫 Má pín OTP, PIN, tàbí ọ̀rọ̀ aṣínà rẹ",
                "🚫 Má fi owó ránṣẹ́ sí ẹni tí o kò mọ",
                "✅ Parẹ́ ìfọ̀rọ̀wánilẹ̀nuwò náà, dí nọ́mbà náà lọ",
                "✅ Sọ fún EFCC tàbí ilé-ifowopamọ rẹ",
            ],
            "learn": "Àwọn ajẹgbé máa ń ṣẹ̀dá ìpayà — wọn á sọ pé 'ṣe báyìí tàbí àkọọ́lẹ̀ rẹ ó máa ti'. Ilé-ifowopamọ tàbí ìjọba gidi kì í ṣiṣẹ́ bẹ́ẹ̀.",
        },
        "hausa": {
            "headline": "⚠️ GARGADI! Wannan sakon ZAMBA ne!",
            "summary": "Don Allah kar ka danna wata hanyar intanet ko aika kuɗi. Wannan zamba ce da ke son satar kuɗin ka da bayanan ka.",
            "what_to_do": [
                "🚫 Kar ka danna wata hanyar intanet da ke cikin sakon",
                "🚫 Kar ka raba OTP, PIN, ko kalmar sirri",
                "🚫 Kar ka aika kuɗi ga wanda ba ka sani ba",
                "✅ Share sakon, toshe lamba",
                "✅ Sanar da EFCC ko bankin ka",
            ],
            "learn": "Masu zamba koyaushe suna ƙirƙirar GAGGAWA — za su ce 'yi yanzu ko asusun ka za a rufe.' Banki na gaske ko gwamnati ba sa aiki haka.",
        },
        "igbo": {
            "headline": "⚠️ ỌCHỊCHỌ IHE NJỌ! Ozi a bụ ỤGHA!",
            "summary": "Biko echefukwa ị pịa njikọ ọ bụla ma ọ bụ zipu ego. Nke a bụ ụgha na-achọ izu ohi ego gị na data gị.",
            "what_to_do": [
                "🚫 Echefukwa ị pịa njikọ ọ bụla n'ime ozi",
                "🚫 Ekwesịghị ịkekọrịta OTP, PIN, ma ọ bụ paswọọdụ gị",
                "🚫 Echefukwa iziga ego onye ọ bụla ị maghị",
                "✅ Hichapụ ozi ahụ, mechie nọmba ahụ",
                "✅ Kọọ EFCC ma ọ bụ ụlọ akụ gị",
            ],
            "learn": "Ndị ohi na-adịkarị mepụta NGWA NGWA — ha ga-asị 'mee ugbu a ma ọ bụ a ga-ezopu akaụntụ gị.' Ụlọ akụ ezigbo ma ọ bụ gọọmentin anaghị arụ ọrụ otú ahụ.",
        },
        "english": {
            "headline": "⚠️ SCAM DETECTED! This message is FRAUDULENT!",
            "summary": "Do not click any link or send money. This is a scam designed to steal your money and personal data.",
            "what_to_do": [
                "🚫 Do not click any links in this message",
                "🚫 Never share your OTP, PIN, or password",
                "🚫 Do not send money to unverified contacts",
                "✅ Delete the message and block the number",
                "✅ Report to EFCC (efccnigeria.org) or your bank",
            ],
            "learn": "Scammers always create URGENCY — they claim your account will be blocked unless you act immediately. Legitimate banks and government agencies never operate this way.",
        },
    },

    # ── SUSPICIOUS ────────────────────────────────────────────────────────
    "SUSPICIOUS": {
        "pidgin": {
            "headline": "🔶 E DIKE! Dis message look suspicious",
            "summary": "We don see some warning signs inside dis message. No rush — verify am before you do anything.",
            "what_to_do": [
                "⚠️ No click any link yet",
                "🔍 Call di organisation directly using official number",
                "❓ Ask trusted person before you act",
                "✅ If e dey look too good to be true, e probably be scam",
            ],
            "learn": "When you no sure about message, always verify through official channels. Google di company name and call dem directly.",
        },
        "yoruba": {
            "headline": "🔶 ÀÀÁ! Ìfọ̀rọ̀wánilẹ̀nuwò yìí dà bíi àrọ̀",
            "summary": "A rí àwọn àmì ìkìlọ̀ nínú ìfọ̀rọ̀wánilẹ̀nuwò yìí. Má yára — ṣàyẹ̀wò rẹ̀ kí o tó ṣe ohunkóhun.",
            "what_to_do": [
                "⚠️ Má tẹ ìsopọ̀ kankan ní báyìí",
                "🔍 Pe àjọ náà tààrà nípasẹ̀ nọ́mbà aṣeyọri",
                "❓ Béèrè lọ́wọ́ ẹni tí o gbẹ́kẹ̀lé ṣáájú kí o tó ṣiṣẹ́",
                "✅ Tó bá dára jù bí ó ṣe yẹ, ó ṣeéṣe jùlọ pé ajẹgbé ni",
            ],
            "learn": "Nígbà tí o bá ní ìdààmú nípa ìfọ̀rọ̀wánilẹ̀nuwò, jẹ́ kí o ṣàyẹ̀wò nípasẹ̀ àwọn ọ̀nà ìṣeyọri.",
        },
        "hausa": {
            "headline": "🔶 LURA! Wannan sako yana da alamun zamba",
            "summary": "Mun ga wasu alamun gargadi a cikin wannan sako. Kar ka gaggawa — tabbatar da shi kafin ka yi komai.",
            "what_to_do": [
                "⚠️ Kar ka danna wata hanyar intanet tukuna",
                "🔍 Kira ƙungiyar kai tsaye ta amfani da lambar hukuma",
                "❓ Tambayi wanda ka amince da shi kafin ka yi aiki",
                "✅ Idan ya yi kyau sosai, mai yiwuwa zamba ce",
            ],
            "learn": "Lokacin da ba ka da tabbas game da sako, tabbatar ta hanyoyin hukuma. Nemi sunan kamfanin kuma kira su kai tsaye.",
        },
        "igbo": {
            "headline": "🔶 DỊKWA MWUTE! Ozi a nwere ihe na-adịghị mma",
            "summary": "Anyị hụrụ ụfọdụ akara ịdọ aka ná ntị n'ozi a. Ọ dịghị mkpa ịgwa ngwa — nyochaa ya tupu imee ihe ọ bụla.",
            "what_to_do": [
                "⚠️ Echefukwa ị pịa njikọ ọ bụla ka ugbu a",
                "🔍 Kpọọ ụlọ ọrụ ahụ ozugbo site na nọmba gọọmenti",
                "❓ Jụọ onye ị tụkwasịrị obi tupu ị arụ ọrụ",
                "✅ Ọ bụrụ na ọ dị mma karịa ka ọ kwesịrị ịdị, ọ pụtara ụgha",
            ],
            "learn": "Mgbe ị ghara ịkwesị ntụkwasị obi maka ozi, nyochaa ya site na ụzọ ọchụchụ gọọmenti.",
        },
        "english": {
            "headline": "🔶 SUSPICIOUS MESSAGE DETECTED",
            "summary": "This message contains warning signs. Do not act immediately — verify through official channels first.",
            "what_to_do": [
                "⚠️ Do not click any links yet",
                "🔍 Call the organisation directly using their official number",
                "❓ Ask a trusted person before proceeding",
                "✅ If it sounds too good or too urgent, it's likely a scam",
            ],
            "learn": "When uncertain, always verify through official channels. Search the company name online and call them directly rather than using contact details in the message.",
        },
    },

    # ── CAUTION ───────────────────────────────────────────────────────────
    "CAUTION": {
        "pidgin": {
            "headline": "🟡 SMALL CAUTION — Take am easy",
            "summary": "Dis message get one or two things wey need attention. E no strong scam, but still be careful.",
            "what_to_do": [
                "🔍 Verify di sender identity before you reply",
                "✅ If na bank message, login through official app instead",
                "💡 When in doubt, call di number on your bank card",
            ],
            "learn": "Even small yellow flags can turn into problems. Always approach unsolicited messages with caution.",
        },
        "english": {
            "headline": "🟡 LOW-LEVEL CAUTION",
            "summary": "This message contains minor warning signals. Exercise caution before responding.",
            "what_to_do": [
                "🔍 Verify the sender's identity before responding",
                "✅ Access banking services through the official app, not links",
                "💡 When in doubt, call the number on the back of your card",
            ],
            "learn": "Even minor red flags deserve attention. Legitimate organisations rarely need urgent action via SMS.",
        },
        "yoruba": {
            "headline": "🟡 ÌKÌLỌ̀ KEKERE — Ṣọ́ra díẹ̀",
            "summary": "Ìfọ̀rọ̀wánilẹ̀nuwò yìí ní àwọn nǹkan kan tó nílò ìfojúsí. Kì í ṣe ajẹgbé tó le, ṣùgbọ́n ṣọ́ra.",
            "what_to_do": [
                "🔍 Ṣàyẹ̀wò ìdánimọ̀ olùránṣẹ́ ṣáájú kí o tó dáhùn",
                "✅ Wọlé bánkì rẹ nípasẹ̀ ohun èlò tàbí ààyè aṣeyọri",
                "💡 Nígbà tí o bá ní ìdààmú, pe nọ́mbà tó wà lẹ́yìn káàdì rẹ",
            ],
            "learn": "Àwọn àmì ìkìlọ̀ kékeré tún ń jẹ́ kí àṣìṣe ṣẹlẹ̀. Ṣọ́ra nígbà tí àwọn ìfọ̀rọ̀wánilẹ̀nuwò tí a kò béèrè fún bá dé.",
        },
        "hausa": {
            "headline": "🟡 GARGADI KAƊAN — Yi hankali",
            "summary": "Wannan sako yana da wasu abubuwa da ke buƙatar kulawa. Ba zamba mai ƙarfi ba, amma yi hankali.",
            "what_to_do": [
                "🔍 Tabbatar da asalin mai aikawa kafin ka amsa",
                "✅ Shiga bankin ka ta hanyar ainihin aikace-aikacen",
                "💡 Idan ba ka da tabbas, kira lambar da ke bayan kakar ka",
            ],
            "learn": "Har ma alamun gargadi ƙanana na iya zama matsala. Koyaushe kusanci sakonnin da ba a nemi ba da hankali.",
        },
        "igbo": {
            "headline": "🟡 NCHECHE OBERE — Dịkwa mwute",
            "summary": "Ozi a nwere ihe ole na ole chọrọ nlelee. Ọ bụghị ụgha siri ike, ma ka dịkwa careful.",
            "what_to_do": [
                "🔍 Nyochaa onwe onye ziputara tupu ị zaghachi",
                "✅ Banye n'ụlọ akụ site na app ndị ọchụchụ, ọ bụghị site na njikọ",
                "💡 Mgbe ọ ghara ịdị mwute, kpọọ nọmba dị n'azụ kaadị gị",
            ],
            "learn": "Ọbụnadị akara obere nwere ike ibu nsogbu. Na-adịkarị n'ụzọ nlebara anya ozi ndị a-azaghị.",
        },
    },

    # ── SAFE ──────────────────────────────────────────────────────────────
    "SAFE": {
        "pidgin": {
            "headline": "✅ E LOOK SAFE — No serious threat found",
            "summary": "We scan dis message and no see serious scam patterns. But still dey careful — no system dey 100%.",
            "what_to_do": [
                "✅ Di message look okay",
                "💡 Still verify any payment request personally",
                "🛡️ Continue dey careful with ALL unsolicited messages",
            ],
            "learn": "Safe today no mean safe tomorrow. Scammers dey always change their style. Stay sharp!",
        },
        "english": {
            "headline": "✅ MESSAGE APPEARS SAFE",
            "summary": "No significant threat patterns detected. However, no automated system is 100% accurate — apply your own judgment.",
            "what_to_do": [
                "✅ This message appears legitimate",
                "💡 Still verify any financial requests in person or via official channels",
                "🛡️ Remain cautious with all unsolicited communications",
            ],
            "learn": "A clean scan does not guarantee safety. Scammers constantly evolve their tactics. Stay informed and trust your instincts.",
        },
        "yoruba": {
            "headline": "✅ Ó DÀBÍì PÀÁPÀÁ — A kò rí ewu tó le",
            "summary": "A ṣàyẹ̀wò ìfọ̀rọ̀wánilẹ̀nuwò yìí, a kò rí àwọn àmì ajẹgbé tó le. Ṣùgbọ́n ṣọ́ra — kò sí ètò tó jẹ́ pé 100%.",
            "what_to_do": [
                "✅ Ìfọ̀rọ̀wánilẹ̀nuwò dàbí ẹni pé ó tọ́",
                "💡 Ṣàyẹ̀wò ìbéèrè owó kankan fún ara rẹ",
                "🛡️ Máa ṣọ́ra pẹ̀lú gbogbo àwọn ìfọ̀rọ̀wánilẹ̀nuwò tí a kò béèrè fún",
            ],
            "learn": "Pàápàápàá lónìí kò túmọ̀ sí pàápàápàá lọ́la. Àwọn ajẹgbé máa ń yí ọ̀nà wọn padà. Dúró lójú!",
        },
        "hausa": {
            "headline": "✅ SAKO YA ZAMA LAFIYA",
            "summary": "Ba a gano manyan alamun zamba ba. Koyaya, babu tsarin da ke da tabbas 100% — yi amfani da hukuncin ka.",
            "what_to_do": [
                "✅ Wannan sako yana da kyau",
                "💡 Har yanzu tabbatar da duk wata buƙatar kuɗi da kanka",
                "🛡️ Ci gaba da taka leda da duk sakonnin da ba a nemi ba",
            ],
            "learn": "Lafiya yau ba yana nufin lafiya gobe ba. Masu zamba koyaushe suna canza salon su. Kasance mai faɗakarwa!",
        },
        "igbo": {
            "headline": "✅ OZI A DỊ MWUTE — Ahụghị ihe ize ndụ ọbịbịa",
            "summary": "Anyị nyochara ozi a ma ahụghị ihe ize ndụ buru ibu. Ma, ọ dịghị usoro nke ziri ezi 100% — jiri ezi uche gị eme ihe.",
            "what_to_do": [
                "✅ Ozi a yiri ka ọ dị ezigbo",
                "💡 Ka nyochaa arịọ ego ọ bụla n'onwe gị",
                "🛡️ Ka nọgide na-elekọta ozi ndị a-achọghị",
            ],
            "learn": "Nchebe taa abụghị nchebe echi. Ndị ohi na-agbanwe ụzọ ha mgbe niile. Nọgide na-etipụ anya!",
        },
    },
}


# ── Category-specific threat explanations ─────────────────────────────────

CATEGORY_EXPLANATIONS = {
    "Bank Impersonation": {
        "pidgin": "Dem dey pretend to be your bank to collect your account details or OTP. Real banks no dey ask for password through SMS.",
        "yoruba": "Wọn ń ṣe bí ilé-ifowopamọ rẹ láti gba àlàyé àkọọ́lẹ̀ rẹ. Ilé-ifowopamọ gidi kì í béèrè fún ọ̀rọ̀ aṣínà nípasẹ̀ SMS.",
        "hausa": "Suna yin kamar bankin ka ne domin su tattara bayanan asusun ka. Banki na gaske ba sa neman kalmar sirri ta SMS.",
        "igbo": "Ha na-eme ka ọ dị ka ụlọ akụ gị iji nweta ihe ndọta akaụntụ gị. Ụlọ akụ ezigbo anaghị arịọ paswọọdụ site na SMS.",
        "english": "Fraudsters impersonate your bank to harvest account credentials. Legitimate banks never request passwords or OTPs via SMS.",
    },
    "OTP Harvesting": {
        "pidgin": "Dem wan collect your One-Time Password to enter your account. Once dem get am, dem don enter. NEVER share OTP with anybody.",
        "yoruba": "Wọn fẹ́ gba Ọ̀rọ̀ Asínà Ìgbà Kan rẹ láti wọlé àkọọ́lẹ̀ rẹ. MÁSE PÍN OTP rẹ fún ẹnikẹ́ni.",
        "hausa": "Suna son tattara Kalmar Sirri Ta Lokaci Guda ka don shiga asusun ka. KADA ka raba OTP ɗinka da kowa.",
        "igbo": "Ha chọrọ ịnweta Okwu-Ọ-Bụ-Otu-Oge gị iji banye akaụntụ gị. EKWESỊGHỊ ịkekọrịta OTP gị n'onye ọ bụla.",
        "english": "Attackers want your One-Time Password to access your account. NEVER share your OTP with anyone — not even someone claiming to be from your bank.",
    },
    "Government Impersonation": {
        "pidgin": "Dem dey pretend to be government (CBN, EFCC, etc) to collect money or personal info. Government no dey contact you through random SMS.",
        "yoruba": "Wọn ń ṣe bíi ìjọba (CBN, EFCC, bẹ́ẹ̀ bẹ́ẹ̀ lọ) láti gba owó tàbí àlàyé ara ẹni. Ìjọba kì í kan sí ọ nípasẹ̀ SMS àìlórúkọ.",
        "hausa": "Suna yin kamar gwamnati ne (CBN, EFCC, da dai sauransu) don tattara kuɗi ko bayanan sirri. Gwamnati ba ta tuntuɓar ka ta hanyar SMS na bazata.",
        "igbo": "Ha na-adị ka gọọmenti (CBN, EFCC, wdg) iji nweta ego ma ọ bụ ozi nke onwe onye. Gọọmenti anaghị kpọtụrụ gị site na SMS ọ bụla.",
        "english": "Scammers pose as government agencies (CBN, EFCC, etc.) to extract money or personal information. Government agencies do not contact citizens via random unsolicited SMS.",
    },
    "Lottery / Prize Scam": {
        "pidgin": "Na lie! You never enter any competition, so how you go win? Dis na classic 419 scam. Dem go ask you pay 'processing fee' before you collect prize wey no exist.",
        "yoruba": "Irọ̀ ni! O kò wọlé ìdíje kankan, báwo ni o ṣe lè ṣẹ́gun? Èyí jẹ́ ajẹgbé 419 ìgbà ayé. Wọn á béèrè owó 'ìmúṣe' ṣáájú kí o tó gba ẹ̀bùn tí kò sí.",
        "hausa": "Karya ce! Ba ka shiga wani gasa ba, ta yaya za ka lashe? Wannan zamba ce ta 419 ta gargajiya. Za su nemi 'kuɗin sarrafawa' kafin ka karɓi kyautar da ba ta wanzu.",
        "igbo": "Ọ bụ ụgha! Abanaghị gị asọmpi ọ bụla, kedu otu ị ga-esi merịa? Nke a bụ ụgha 419 oge ochie. Ha ga-arịọ gị 'ụgwọ nhazi' tupu ị nara ihe onyinye na-adịghị.",
        "english": "This is a classic 419 advance-fee fraud. You did not enter any competition. They will ask you to pay a 'processing fee' before collecting a prize that does not exist.",
    },
    "Crypto / Investment Fraud": {
        "pidgin": "No genuine investment dey guarantee profit. Anybody wey promise you 'guaranteed returns' na scammer. E fit be Ponzi scheme.",
        "yoruba": "Kò sí ìdókòwò tó ń ṣe ìdánilójú èrè. Ẹnikẹ́ni tó ń ṣèlérí 'àǹfààní tó dájú' jẹ́ ajẹgbé. Ó ṣeéṣe pé àpèjúwe Ponzi ni.",
        "hausa": "Babu zuba jari na gaske da ke ba da tabbacin riba. Duk wanda ke yin alkawarin 'riba mai tabbas' mai zamba ne. Yana iya zama tsarin Ponzi.",
        "igbo": "Ọ dịghị mkpachi ezigbo na-enye nkwa uru. Onye ọ bụla na-akwa nkwa 'uru nke a kwesịrị ntụkwasị obi' bụ onye ohi. Ọ nwere ike ịbụ atụmatụ Ponzi.",
        "english": "No legitimate investment guarantees fixed returns. Anyone promising 'guaranteed profits' is running a fraud — likely a Ponzi or pyramid scheme.",
    },
    "Romance Scam": {
        "pidgin": "Online love no always real. People dey create fake profiles and pretend to love you before dem ask for money. Once dem ask for money or package fee — na scam.",
        "yoruba": "Ìfẹ́ orí ìnẹ́tì kì í jẹ́ ògbólógbòó. Àwọn ènìyàn ń ṣẹ̀dá àwòrán ìdánimọ̀ irọ̀ tí wọn ó fi ṣe bí wọn ní ìfẹ́ rẹ ṣáájú kí wọn tó béèrè owó.",
        "hausa": "Soyayyar kan layin intanet ba ta kasance ta gaske ba. Mutane suna ƙirƙirar bayanan karya kuma suna yin kamar suna son ka kafin su nemi kuɗi.",
        "igbo": "Ihunanya n'ịntanetị abụghị ezigbo mgbe niile. Ndị mmadụ na-emepụta profaịlụ ụgha ma na-eme ka ị chere na ha hụrụ gị n'anya tupu ha arịọ ego.",
        "english": "Online relationships can be fabricated. Scammers build fake emotional connections over weeks before requesting money for emergencies, customs fees, or travel. Any financial request should be treated as a red flag.",
    },
    "Urgency Manipulation": {
        "pidgin": "Urgency na manipulation tool. Dem wan make you no think well before you act. Real organisations give you time to verify.",
        "yoruba": "Kíákíá jẹ́ irinṣẹ́ ìmọ́jútó. Wọn fẹ́ kí o má ronú dáadáa ṣáájú kí o tó ṣiṣẹ́. Àwọn àjọ gidi máa ń fún ọ ní àkókò láti ṣàyẹ̀wò.",
        "hausa": "Gaggawa kayan aikin sarrafa hankali ne. Suna son ka kar ka yi tunani sosai kafin ka yi aiki. Ƙungiyoyi na gaske suna ba ka lokaci don tabbatarwa.",
        "igbo": "Ngwa ngwa bụ ngwa iji jikwaa mmadụ. Ha chọrọ ka ị ghara iche nke ọma tupu imee ihe. Ụlọ ọrụ ezigbo na-enye gị oge iji nyochaa.",
        "english": "Urgency is a psychological manipulation tool designed to bypass rational thinking. Legitimate organisations always give you time to verify independently.",
    },
}


def get_warning(verdict: str, language: str, category: Optional[str] = None) -> dict:
    """Returns localised warning content for a given verdict, language, and threat category."""
    lang = language.lower()
    if lang not in TEMPLATES.get(verdict, {}):
        lang = "english"

    base = TEMPLATES.get(verdict, {}).get(lang, TEMPLATES[verdict]["english"])

    # Add category-specific explanation if available
    category_explanation = None
    if category and category in CATEGORY_EXPLANATIONS:
        cat_data = CATEGORY_EXPLANATIONS[category]
        category_explanation = cat_data.get(lang, cat_data.get("english", ""))

    return {
        "language": LANGUAGES.get(language, LANGUAGES["english"]),
        "headline": base["headline"],
        "summary": base["summary"],
        "what_to_do": base["what_to_do"],
        "learn": base["learn"],
        "category_explanation": category_explanation,
    }


def get_available_languages() -> list[dict]:
    return [{"id": k, **v} for k, v in LANGUAGES.items()]
