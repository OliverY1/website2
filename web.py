import random
import streamlit as st
from streamlit_option_menu import option_menu as op

st.set_page_config(page_title="BangBros", page_icon="random", layout="centered", initial_sidebar_state="auto", menu_items=None)

def ragg():
    raggningsrepliker = [
    "Är du en kamera? För varje gång jag ser dig ler jag.",
    "Finns det en flygplats i närheten? För mina fjärilar i magen är på väg att lyfta.",
    "Har du en karta? Jag har gått vilse i dina ögon.",
    "Tror du på kärlek vid första ögonkastet eller ska jag gå förbi igen?",
    "Kan jag få ditt telefonnummer? Jag verkar ha tappat mitt.",
    "Du måste vara trött för du har sprungit runt i mina tankar hela dagen.",
    "Om skönhet var ett brott skulle du vara livstidsdömd.",
    "Kan jag få låna din mobil? Jag måste ringa min mamma och säga att jag har träffat min drömtjej.",
    "Har du feber? För du är het!",
    "Har du ett plåster? För jag skrapade just mitt knä när jag föll för dig.",
    "Tror du på ödet? För jag tror just att jag har träffat mitt.",
    "Är du trött? För du har sprungit runt i mina drömmar hela natten.",
    "Om du var ett ord skulle du vara 'VACKER' i ordboken.",
    "Om skönhet var tid skulle du vara en evighet.",
    "Förlorade du din telefonnummer? Nej? Det är konstigt, för jag trodde du föll från himlen.",
    "Ursäkta mig, men jag tror jag förlorade mitt telefonnummer. Kan jag få ditt?",
    "Vet du vad som skulle se bra ut på dig? Jag.",
    "Förutom att vara vacker, vad gör du för skojigt?",
    "Jag tror du har något i dina ögon... Vänta, det är bara gnistan från hur du ser på mig.",
    "Är du en trollkarl? För när jag ser dig försvinner allt annat.",
    "Finns det en flygplats i närheten? För varje gång jag ser dig känns det som om jag lyfter.",
    "Är du trött? För du har sprungit runt i mina tankar hela natten.",
    "Om skönhet var en stjärna skulle du lysa starkast.",
    "Har du en karta? För jag har gått vilse i dina ögon.",
    "Är du en alien? För du har precis kidnappat mitt hjärta.",
    "Jag är inte en fotograf, men jag kan definitivt föreviga oss tillsammans.",
    "Är du en parkeringsbiljett? För du har 'finaste' skrivet över hela dig.",
    "Om jag var en katt skulle jag spendera alla mina liv med dig.",
    "Jag är inte en tjuv, men jag skulle gärna stjäla ditt hjärta.",
    "Finns det en spegel i din ficka? För jag kan se mig själv i dina byxor.",
    "Har du en solskensdag? För du får min dag att lysa upp."
    ]
    i = random.randint(0, 29)
    return raggningsrepliker[i]



with st.sidebar:
    selected = op(
        menu_title="Meny",
        options=["Hem", "Om oss", "Generator"],
        icons=["house-heart-fill", "calendar2-heart-fill"],
        menu_icon="house-heart-fill",
        default_index=0,
    )

def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()


def set_background(png_file):
    bin_str = get_base64(png_file)
    page_bg_img = '''
    <style>
    .stApp {
    background-image: url("data:image/png;base64,%s");
    background-size: cover;
    }
    </style>
    ''' % bin_str
    st.markdown(page_bg_img, unsafe_allow_html=True)


col1, col2, col3, col4 = st.columns([4, 4, 4, 4])

if selected == "Hem":
    set_background("bckg.png")
    st.title("BangBros")
    st.header("Stay tuned for more")

    with col1:
        st.image("Laok.jpg")
        if 'button' not in st.session_state:
            st.session_state.button = False

        def click_button():
            st.session_state.button = not st.session_state.button

        st.button('Laok', on_click=click_button)

        if st.session_state.button:
    
            st.write("Min favorit kurd. Laok är den klantigaste av dem alla. Han har en förmåga att kliva rakt in i situationer utan att tänka och orsakar oavsiktliga skador och olyckor vart han än går. Hans närvaro är som en ticking time bomb av klumpighet.")
    
            
    with col2:
        st.image("Melle2.jpg")
        if st.button("Melvin"):
            st.write("Min favorit apa. Melvin är den drömmande idealisten i gruppen. Han har alltid sitt huvud i molnen och tror på det bästa i alla människor. Tyvärr gör hans naivitet honom till ett lätt byte för luriga typer.") 

    with col3:
        st.image("om.jpg")
        if st.button("Omar"):
            st.write("Min favorit sandätare. Omar är den som alltid tror sig ha lösningen på allt, men i själva verket är hans idéer vanligtvis helt bisarra och leder oftast till kaos. Han är den som alltid föreslår att de ska göra något extremt dumt bara för att det låter \"roligt\".")
    
    with col4:
        st.image("jos.jpg")
        if st.button("Josef"):
            st.write("Min favorit vattentank. Josef är den klumpiga medlemmen av gruppen. Han är ökänd för att ständigt stöta till saker, spilla saker och allmänt orsaka kaos runt omkring sig.")

if selected == "Om oss":
    set_background("bckg.png")
    st.title("Om oss")
    st.write("I en dold by, insvept i skogens tysta sånger och månens sken, samlas fem själar – Oliver, Laok, Melvin, Josef och Omar. Deras liv flätas samman av en gåtfull ödets tråd. Oliver bär en nyckel smidd av månens ljus, Laok har en gåva från jorden, Melvin bär solens strålar, Josef bär gryningens nyckel och Omar bär drömmarnas gåva. Deras gemensamma sökande tar dem genom dimmiga skogspassager och tätt lövverk, på jakt efter sanningen som vilar i det förlorade arvets skuggor.")

if selected == "Generator":
    st.title("Generera olika saker")
    if st.button("Raggningsreplik"):
        st.write(ragg())
