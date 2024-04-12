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
            st.text("Min favorit apa.\nMelvin är den \ndrömmande idealisten \ni gruppen. Han har \nalltid sitt huvud i \nmolnen och tror på \ndet bästa i alla \nmänniskor. Tyvärr \ngör hans naivitet honom \ntill ett lätt byte \nför luriga typer.") 

    with col3:
        st.image("om.jpg")
        if st.button("Omar"):
            st.text("Min favorit sandätare.\nOmar är den som alltid \ntror sig ha lösningen på \nallt, men i själva verket \när hans idéer vanligtvis \nhelt bisarra och \nleder oftast till \nkaos. Han är den \nsom alltid föreslår \natt de ska göra \nnågot extremt dumt \nbara för att det \nlåter \"roligt\".")
    
    with col4:
        st.image("jos.jpg")
        if st.button("Josef"):
            st.text("Min favorit vattentank.\nJosef är den klumpiga \nmedlemmen av gruppen. \nHan är ökänd för att \nständigt stöta till saker, \nspilla saker och allmänt \norsaka kaos runt \nomkring sig.")

if selected == "Om oss":
    st.title("Vi är BangBros")

