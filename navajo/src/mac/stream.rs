use core::{
    marker::PhantomData,
    task::Poll::{self, *},
};

use futures::{Future, Stream};
use pin_project::pin_project;

use crate::error::MacVerificationError;

use super::{verifier::Verifier, Computer, Mac, Tag};

const BLOCK_SIZE: usize = 256; // todo: profile this

pub trait StreamMac: Stream {
    fn compute_mac(self, mac: &Mac) -> ComputeStream<Self, Self::Item>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
    {
        ComputeStream::new(self, mac.into())
    }

    fn verify_mac<T>(self, tag: T, mac: &Mac) -> VerifyStream<Self, Self::Item, T>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
        T: AsRef<Tag> + Send + Sync,
    {
        let verify = Verifier::new(tag, mac);
        VerifyStream::new(self, verify)
    }
}
impl<T> StreamMac for T
where
    T: Stream,
    T::Item: AsRef<[u8]>,
{
}

#[pin_project]
pub struct ComputeStream<S, D>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
{
    #[pin]
    stream: S,
    compute: Option<Computer>,
    _phantom: PhantomData<D>,
}

impl<S, D> ComputeStream<S, D>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
{
    pub fn new(stream: S, compute: Computer) -> Self {
        let compute = Some(compute);
        Self {
            stream,
            compute,
            _phantom: PhantomData,
        }
    }
}

impl<S, D> Future for ComputeStream<S, D>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
{
    type Output = Tag;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let mut this = self.project();

        let mut compute = this.compute.take().unwrap();
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Ready(response) => match response {
                    Some(data) => compute.update(data.as_ref()),
                    None => return Poll::Ready(compute.finalize()),
                },
                Pending => {
                    this.compute.replace(compute);
                    return Pending;
                }
            };
        }
    }
}

#[pin_project]
pub struct VerifyStream<S, D, T>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
    T: AsRef<Tag> + Send + Sync,
{
    #[pin]
    stream: S,
    verifier: Option<Verifier<T>>,
    _phantom: PhantomData<D>,
}
impl<S, D, T> VerifyStream<S, D, T>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
    T: AsRef<Tag> + Send + Sync,
{
    pub fn new(stream: S, verify: Verifier<T>) -> Self {
        let verifier = Some(verify);
        Self {
            stream,
            verifier,
            _phantom: PhantomData,
        }
    }
}

impl<S, D, T> Future for VerifyStream<S, D, T>
where
    S: Stream<Item = D>,
    D: AsRef<[u8]>,
    T: AsRef<Tag> + Send + Sync,
{
    type Output = Result<Tag, MacVerificationError>;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut verifier = this.verifier.take().unwrap();
        loop {
            match this.stream.as_mut().poll_next(cx) {
                Ready(response) => match response {
                    Some(data) => verifier.update(data.as_ref()),
                    None => return Poll::Ready(verifier.finalize()),
                },
                Pending => {
                    this.verifier.replace(verifier);
                    return Pending;
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::Algorithm;
    use futures::{stream, StreamExt};

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_mac_stream() {
        let long_str = r#"[cia.gov](https://www.cia.gov/stories/story/navajo-code-talkers-and-the-unbreakable-code/)

        Navajo Code Talkers and the Unbreakable Code
        ============================================
        
        In the heat of battle, it is of the utmost importance that messages are delivered and received as quickly as possible. It is even more crucial that these messages are encoded so the enemy does not know about plans in advance.
        
        During World War II, the Marine Corps used one of the thousands of languages spoken in the world to create an unbreakable code: Navajo.  
        World War II wasn’t the first time a Native American language was used to create a code.
        
        During World War I, the Choctaw language was used in the transmission of secret tactical messages. It was instrumental in a successful surprise attack against the Germans.
        
        Germany and Japan sent students to the United States after World War I to study Native American languages and cultures, such as Cherokee, Choctaw, and Comanche.
        
        Because of this, many members of the U.S. military services were uneasy about continuing to use Code Talkers during World War II. They were afraid the code would be easily cracked, but that was before they learned about the complexity of Navajo.
        
        Philip Johnston’s Brainchild
        ----------------------------
        
        In 1942, Philip Johnston was reading a newspaper article about an armored division in Louisiana that was attempting to come up with another code using Native American languages. Johnston knew the perfect Native American language to utilize in a new, unbreakable code.
        
        As a child, Johnston spent most of his childhood on a Navajo reservation while his parents served there as missionaries. He grew up learning the Navajo language and customs.
        
        Johnston became so fluent in the Navajo language that he was asked at age 9 to serve as an interpreter for a Navajo delegation sent to Washington, D.C., to lobby for Indian rights.
        
        In spite of concerns about the security of a code based on a Native American language, the U.S. Marine Corps decided to give Johnston’s idea a try. They approved a pilot project with 30 Navajos and allowed Johnston to enlist and participate in the program.
        
        Getting Started
        ---------------
        
        The first 29 recruited Navajos (one dropped out) arrived at Camp Elliott near San Diego in May 1942. One of the first tasks for these recruits was to develop a Navajo code.
        
        The Navajo language seemed to be the perfect option as a code because it is not written and very few people who aren’t of Navajo origin can speak it.  
        However, the Marine Corps took the code to the next level and made it virtually unbreakable by further encoding the language with word substitution.
        
        During the course of the war, about 400 Navajos participated in the code talker program.
        
        The Code
        --------
        
        ### Word Association
        
        The Navajo recruits began developing the code by taking words from their language and applying to them to implements of war. For example, the names of different birds were used to stand for different kinds of planes.  
        The initial code consisted of 211 vocabulary terms, which expanded to 411 over the course of the war.
        
        ### A is for Apple…
        
        In addition, an alphabet system (see below) was also developed by the Code Talkers. It would be used to spell out some of the words not found in Navajo vocabulary.
        
        The first letter of a Navajo word corresponded with one of the 26 letters in the English alphabet. Several different words were chosen to represent the more commonly used letters in order to make the code even more secure.  
        \*Click here to see the entire [Navajo Code Talker Dictionary](https://www.history.navy.mil/research/library/online-reading-room/title-list-alphabetically/n/navajo-code-talker-dictionary.html) on the US Navy history page.
        
        In Record Time
        --------------
        
        A skeptical lieutenant decided to test their skills and the code before trusting them to deliver actual combat messages.
        
        The Code Talkers successfully translated, transmitted and re-translated a test message in two and a half minutes. Without using the Navajo code, it could take hours for a soldier to complete the same task.
        
        From then on, the Code Talkers were used in every major operation involving the Marines in the Pacific theater. Their primary job was to transmit tactical information over telephone and radio.
        
        During the invasion of Iwo Jima, six Navajo Code Talkers were operating continuously. They sent more than 800 messages. All of the messages were transmitted without error.
        
        The Navajo Code Talkers were treated with the utmost respect by their fellow marines. Major Howard Connor, who was the signal officer of the Navajos at Iwo Jima, said, “Were it not for the Navajos, the Marines would never have taken Iwo Jima.”
        
        Honors
        ------
        
        The hard work of the Navajo Code Talkers was not recognized until after the declassification of the operation in 1968.
        
        President Ronald Reagan gave the Code Talkers a Certificate of Recognition and declared August 14 “Navajo Code Talkers Day” in 1982.
        
        In 2000, President Bill Clinton signed a law which awarded the Congressional Gold Medal to the original 29 Code Talkers.
        
        President George W. Bush presented the medals to the four surviving Code Talkers at a ceremony held in the Capitol Rotunda in Washington in July 2001.
        
        Code Challenge
        --------------
        
        ### Want to try your hand at deciphering a code in Navajo?
        
        Use the Navajo Code Talker Dictionary below and then click the link to see if you are correct.
        
        Decipher the following code to find out who suggested using the Navajo language for secure communications:
        
        Ne-Zhoni-Lin-Tkin-Ah-Jad-Tkin-Ne-Zhoni Ah-Ya-Tsinne-A-Kha-Lin-A-Chin-Klesh-D-Ah-A-Kha-A-Chin
        
        Decipher the code below to find out during what battle the Navajo Code Talkers to help gain a U.S. victory:
        
        Tkin-Gloe-lh-A-Kha Ah-Ya-Tsinne-Tkin-Tsin-Tliti-Tse-Nill"#;

        let hex_data = long_str.as_bytes().chunks(16).map(|c| c.to_vec());

        let key = hex::decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
            .unwrap();
        let mac =
            crate::mac::Mac::new_with_external_key(&key, Algorithm::Sha256, None, None).unwrap();

        let stream_data = stream::iter(hex_data);
        let computed = stream_data.compute_mac(&mac).await;
        let expected =
            hex::decode("72fd211411c56848ccc90eafd19269a7fa1c3067d5bce20836575d786f828f4e")
                .unwrap();

        assert_eq!(&computed, &expected);
    }
}
