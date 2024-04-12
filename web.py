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
            st.text("Min favorit kurd. \nLaok är den \nklantigaste av dem \nalla. \nHan har en förmåga \natt kliva rakt in \ni situationer utan \natt tänka och \norsakar \noavsiktliga skador \noch olyckor vart \nhan \nän går. Hans \nnärvaro \när som en \nticking time bomb \nav \nklumpighet.")
    
    with col2:
        st.image("Melle2.jpg")
        if st.button("Melvin"):
            st.text("Min favorit apa.\nMelvin är den drömmande idealisten i gruppen. Han har alltid sitt huvud i molnen och tror på det bästa i alla människor. Tyvärr gör hans naivitet honom till ett lätt byte för luriga typer.") 

    with col3:
        st.image("om.jpg")
        if st.button("Omar"):
            st.text("Min favorit sandätare.\nOmar är den som alltid tror sig ha lösningen på allt, men i själva verket är hans idéer vanligtvis helt bisarra och leder oftast till kaos. Han är den som alltid föreslår att de ska göra något extremt dumt bara för att det låter \"roligt\".")
    
    with col4:
        st.image("jos.jpg")
        if st.button("Josef"):
            st.text("Min favorit vattentank.\nJosef är den klumpiga medlemmen av gruppen. Han är ökänd för att ständigt stöta till saker, spilla saker och allmänt orsaka kaos runt omkring sig.")

if selected == "Om oss":
    st.title("Vi är BangBros")
