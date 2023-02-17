use core::mem;

use alloc::vec::Vec;
use futures::Stream;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};

const BUFFER_SIZE: usize = 64; // Todo: profile this

use super::{ComputeStream, ComputeTryStream, Context, Mac, Tag};

/// Computes a [`Tag`] for the provided bytes using each key in [`Mac`].
pub struct Computer {
    contexts: Vec<Context>,
    buffer: Vec<u8>,
}

impl Computer {
    pub fn new<M>(mac: M) -> Self
    where
        M: AsRef<super::Mac>,
    {
        let keys = mac.as_ref().keyring().keys();
        let mut contexts = Vec::with_capacity(keys.len());

        for key in keys {
            contexts.push(key.new_context());
        }

        Self {
            contexts,
            buffer: Vec::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend(data.iter());

        // there's no reason to keep a buffer if there's only one key
        if self.contexts.len() == 1 {
            let buf = self.buffer.split_off(0);
            self.contexts[0].update(&buf);
        }

        // in the event there are mutliple keys, the data is buffered and
        // chunked. This is because updates are possibly run in parallel,
        // resulting in the potential memory usage of n * d where n is the
        // number of keys and d is size of the data.
        while self.buffer.len() >= BUFFER_SIZE {
            let idx = if self.buffer.len() > BUFFER_SIZE {
                BUFFER_SIZE
            } else {
                self.buffer.len()
            };
            let buf = self.buffer.split_off(idx);
            let chunk: Vec<u8> = mem::replace(&mut self.buffer, buf);
            self.update_chunk(chunk);
        }
    }
    pub fn finalize(mut self) -> Tag {
        let chunk: Vec<u8> = mem::take(&mut self.buffer);
        self.update_chunk(chunk);
        Tag::new(self.contexts.into_iter().map(|ctx| ctx.finalize()))
    }

    pub fn stream<S, D>(self, stream: S) -> ComputeStream<S, S::Item>
    where
        D: AsRef<[u8]>,
        S: Stream<Item = D>,
    {
        ComputeStream::new(stream, self)
    }

    pub fn try_stream<S, D, E>(self, stream: S) -> ComputeTryStream<S, S::Ok, S::Error>
    where
        D: AsRef<[u8]>,
        E: Send + Sync,
        S: futures::TryStream<Ok = D, Error = E>,
    {
        ComputeTryStream::new(stream, self)
    }

    fn update_chunk(&mut self, chunk: Vec<u8>) {
        if self.contexts.len() > 1 {
            self.contexts.par_iter_mut().for_each(|ctx| {
                ctx.update(&chunk);
            });
        } else {
            self.contexts.iter_mut().for_each(|ctx| {
                ctx.update(&chunk);
            });
        }
    }
}

impl<T> From<&T> for Computer
where
    T: AsRef<Mac>,
{
    fn from(mac: &T) -> Self {
        Self::new(mac)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for Computer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::mac::Algorithm::Sha256;

    use super::*;

    #[test]
    fn test_basic() {
        let key = hex::decode("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649")
            .unwrap();
        let expected =
            hex::decode("20fd9496199a45e414bdd82ce531ec681200ce459ab4a85239cc6076dc5de225")
                .unwrap();
        let mac = crate::mac::Mac::new_with_external_key(&key, Sha256, None, None).unwrap();

        let mut hasher = Computer::new(&mac);
        hasher.update(b"message");
        let tag = hasher.finalize();
        assert_eq!(tag.omit_header().unwrap(), &expected[..]);
    }
    #[test]
    fn test_chunked() {
        let key = hex::decode("52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649")
            .unwrap();
        let mut mac = crate::mac::Mac::new_with_external_key(&key, Sha256, None, None).unwrap();

        let second_key =
            hex::decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
                .unwrap();
        let second_key = mac
            .add_external_key(&second_key, Sha256, None, None)
            .unwrap();
        mac.promote_key(&second_key).unwrap();
        let expected =
            hex::decode("72fd211411c56848ccc90eafd19269a7fa1c3067d5bce20836575d786f828f4e")
                .unwrap();

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

        let mut hasher = Computer::new(&mac);
        hasher.update(long_str.as_bytes());
        let tag = hasher.finalize();
        assert_eq!(tag.omit_header().unwrap().len(), expected[..].len());
        assert_eq!(tag.omit_header().unwrap(), &expected[..]);
        // assert_eq!(
        //     tag.omit_header().as_ref(),
        //     hex::decode("1b2dd9405426e0c7de12085c5ddd7fdee131064112cd6249ed4af2d2a3c69295")
        //         .unwrap()
        //         .as_slice()
        // );
    }
}
