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
            st.text("Min favorit kurd. \nLaok är den \nklantigaste av dem \nalla. Han har \nen förmåga \natt kliva rakt in \ni situationer utan \natt tänka och \norsakar oavsiktliga \nskador \noch olyckor vart \nhan än går. \nHans närvaro \när som en \nticking time bomb \nav klumpighet.")
    
    with col2:
        st.image("Melle2.jpg")
        if st.button("Melvin"):
            st.text("Min favorit apa.\nMelvin är den \ndrömmande \nidealisten i \ngruppen. Han har \nalltid sitt huvud i \nmolnen och tror på \ndet bästa i alla \nmänniskor. Tyvärr \ngör hans naivitet \nhonom till \nett lätt byte \nför luriga typer.") 

    with col3:
        st.image("om.jpg")
        if st.button("Omar"):
            st.text("Min favorit \nsandätare.Omar är \nden som alltid \ntror sig ha \nlösningen på \nallt, men i själva \nverket \när hans idéer \nvanligtvis \nhelt bisarra och \nleder oftast till \nkaos. Han är den \nsom alltid föreslår \natt de ska göra \nnågot extremt dumt \nbara för att det \nlåter \"roligt\".")
    
    with col4:
        st.image("jos.jpg")
        if st.button("Josef"):
            st.text("Min favorit \nvattentank. Josef \när den klumpiga \nmedlemmen av \ngruppen. \nHan är ökänd för \natt ständigt \nstöta till saker, \nspilla saker och \nallmänt \norsaka kaos runt \nomkring sig.")

if selected == "Om oss":
    st.title("Vi är BangBros")
    st.text("I en dold by, insvept i skogens tysta sånger och månens sken, samlas fem själar.")
    st.text("Oliver, Laok, Melvin, Josef och Omar. Deras liv flätas samman av en gåtfull")
    st.text("ödets tråd. Oliver bär en nyckel smidd av månens ljus, Laok har en gåva från jorden,")
    st.text("Melvin bär solens strålar, Josef bär gryningens nyckel och Omar bär drömmarnas gåva.")
    st.text("Deras gemensamma sökande tar dem genom dimmiga skogspassager och tätt lövverk,")
    st.text("på jakt efter sanningen som vilar i det förlorade arvets skuggor.Omar, den vise")
    st.text("och den som ser bortom horisonten, bär med sig en nyckel som funnits i de djupaste")
    st.text("utvalda att lösa gåtornas gåta och återuppliva minnet av det förlorade arvet.")
    st.text("drömmarna. Dessa fem själar, förenade av ödets omsorgsfulla hand, är de Genom")
    st.text("dimmornas slöjor och skuggornas dans ska de vandra, på jakt efter sanningen ")
    st.text(" bakom Gåtornas Arvtagare och sanningen som gömmer sig i deras hjärtan.")


