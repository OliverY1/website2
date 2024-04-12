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


col1, col2 = st.columns([4, 4])

if selected == "Hem":
    st.title("BangBros")
    st.header("Stay tuned for more")

    with col1:
        st.image("Laok.jpg")
        if st.button("Laok"):
            st.text("Min favorit kurd")
    
    with col2:
        st.image("Melle2.jpg")
        if st.button("Melvin"):
            st.text("Min favorit apa")

if selected == "Om oss":
    st.title("Vi är BangBros")
    st.text("Vi på BangBros AB planerar ett attentat i Kurdistan, donera till oss")

