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
    st.text("I dimmornas skimmer, där skogens tysta viskningar fångar öronen på de vaksamma och nattens stjärnor lyser som lysmaskar i det svarta täcket av himlen, uppenbarar sig en gåta vars svar är skrivet i stjärnorna: "Gåtornas Arvtagare."

I en by gömd bland träden, där tidens flod bär med sig minnen från forna dagar och skuggorna dansar sin tysta dans på de mossklädda stenarna, samlas fem föräldralösa själar, var och en bärande en nyckel till en gåta som sträcker sig över världar och tider.

Oliver, med sina ljusa ögon som speglar månens sken, bär med sig en gnista av äventyr och en nyckel som smiddes i skymningens glöd.

Laok, tystlåten och vis, vägleder med sina ord de andra genom dunklet, och i sin hand bär han en nyckel som varit förborgad i jordens inre.

Melvin, den ständige optimisten, sprider sitt skratt över dalen och bär på en nyckel som hittats bland de glömda sidorna av en bok.

Josef, med sitt mod som starkare än stål, leder de andra framåt och bär med sig en nyckel som skapats av ljuset från gryningen.

Omar, den vise och den som ser bortom horisonten, bär med sig en nyckel som funnits i de djupaste drömmarna.

Dessa fem själar, förenade av ödets omsorgsfulla hand, är de utvalda att lösa gåtornas gåta och återuppliva minnet av det förlorade arvet.

Genom dimmornas slöjor och skuggornas dans ska de vandra, på jakt efter sanningen bakom Gåtornas Arvtagare och sanningen som gömmer sig i deras hjärtan."

