import streamlit as st
from streamlit_option_menu import option_menu as op

row1 = st.container()
row2 = st.container()

with st.sidebar:
    selected = op(
        menu_title="Meny",
        options=["Hem", "Om oss"],
        icons=["house-heart-fill", "calendar2-heart-fill"],
        menu_icon="house-heart-fill",
        default_index=0,
    )


col1, col2, col3, col4 = st.columns([4, 4, 4, 4])

if selected == "Hem":
    st.title("BangBros")
    st.header("Stay tuned for more")

    with col1:
        st.image("Laok.jpg")
        if st.button("Laok"):
            st.write("Min favorit kurd. Laok är den klantigaste av dem alla. Han har en förmåga att kliva rakt in i situationer utan att tänka och orsakar oavsiktliga skador och olyckor vart han än går. Hans närvaro är som en ticking time bomb av klumpighet.")
    
    with col2:
        st.image("Melle2.jpg")
        if st.button("Melvin"):
            st.write("Min favorit apa.Melvin är den drömmande idealisten i gruppen. Han har alltid sitt huvud i molnen och tror på det bästa i alla människor. Tyvärr gör hans naivitet honom till ett lätt byte för luriga typer.") 

    with col3:
        st.image("om.jpg")
        if st.button("Omar"):
            st.write("Min favorit sandätare.Omar är den som alltid tror sig ha lösningen på allt, men i själva verket är hans idéer vanligtvis helt bisarra och leder oftast till kaos. Han är den som alltid föreslår att de ska göra något extremt dumt bara för att det låter \"roligt\".")
    
    with col4:
        st.image("jos.jpg")
        if st.button("Josef"):
            st.write("Min favorit vattentank. Josef är den klumpiga medlemmen av gruppen. Han är ökänd för att ständigt stöta till saker, spilla saker och allmänt orsaka kaos runt omkring sig.")

if selected == "Om oss":
    st.title("Om oss")
    st.write("I en dold by, insvept i skogens tysta sånger och månens sken, samlas fem själar – Oliver, Laok, Melvin, Josef och Omar. Deras liv flätas samman av en gåtfull ödets tråd. Oliver bär en nyckel smidd av månens ljus, Laok har en gåva från jorden, Melvin bär solens strålar, Josef bär gryningens nyckel och Omar bär drömmarnas gåva. Deras gemensamma sökande tar dem genom dimmiga skogspassager och tätt lövverk, på jakt efter sanningen som vilar i det förlorade arvets skuggor.")

