---
title: "루마니아 여행과 함께하는 Defcamp CTF 2022 Final 참가 후기 - part 3. Defcamp CTF Final 그리고.."
author: Imreplay
categories:
  - review
tags: [travel,defcamp, ctf]

---

> 이전 이야기 :  exploit 자동화 도구를 테스트하던 팀원들은 결국 아침을 맞게 되는데…

# 가자 Defcamp로!

드디어 대망의 Defcamp CTF 본선의 아침이 밝았다. 다들 피곤에 ~~찌들어~~ 지쳐있는 모습이었지만 본선에 진출한다는 기대감에 설레어하고 있었다.

![Untitled.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/Untitled.jpg)

## 한국인은 밥심이지 음음

다같이 호텔 조식을 먹으며 이런 저런 대화를 나누는데 주변 테이블에 앉는 사람들 모두가 대회에 참여하는 사람으로 보였다. 구글 티셔츠를 입고 있는 사람, 다른 CTF 티셔츠를 입고 온 사람들 등등..

![20221110_074850.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_074850.jpg)

## 드디어 대회! 가즈아ㅏㅏㅏ

가볍게 식사를 마친 후 오전 8시 30분에 대회 장소로 이동하는 셔틀버스를 제공해준다는 소식에 부지런하게 아침을 먹고 대회 장소로 이동했다. 각자 가방을 챙겨 호텔 로비에서 기다리는 중!

![Untitled.png](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/Untitled.png)

대회는 **Aurrum Palace** 라는 곳에서 진행되었다. 들어가니 사전에 이메일로 전달 받은 Check-in 코드를 입력하면 목에 걸 수 있는 패스를 발급해줬다. 

![20221110_232313.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_232313.jpg)

도착 후 팀원들은 분주하게 움직이기 시작했다. 각자 할당 받은 VPN에 접속해 대회 네트워크에 연결하고, 약 1시간 동안 주어진 서버에 있는 취약점을 찾아 패치하고 이에 대한 공격 코드를 작성해, 다른 팀의 flag를 가져오면 되는 방식이었다. 일부 팀원은 exploit 도구를 설정했고 다른 팀원들은 빠르게 취약점을 찾아나갔다.

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_173120.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_090910.jpg">
</figure>


<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_111624.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_134113.jpg">
</figure>


<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_185603.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_185551.jpg">
</figure>


다른 팀 팀원들 역시 빠르게 문제를 풀어나갔고 다들 집중해서 취약점을 찾아갔다.

![KakaoTalk_20221110_161351466.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/KakaoTalk_20221110_161351466.jpg)

대회 중간마다 레드불도 나눠주시고 점심(맛은 음…)도 주셔서 지루하지 않게 대회에 참여할 수 있었다.

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_143254.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_143043.jpg">
</figure>


## 하지만 언제나 조져지는건 나였다

대회 시작 후 1시간이 경과하고… 드디어 첫 번째 exploit을 실행 시키려는데..!

어라 이건 뭔가 잘못됐다…! 문제를 풀고 flag를 가져오는 것 까지는 잘 작동했지만, flag를 제출하는 과정에서 문제가 생겼다. 

지금에서 생각해보면 간단한 문제였다. `aiohttp` 에서 보내는 요청에서 ssl 에러가 발생한 것이었는데, 시간에 쫓겨 당황한 탓인지 requests 모듈을 사용해 개발한 것으로 생각하고 에러를 고치려고 시도하다 보니, flag인증은 다른 팀원이 로그에서 Ctrl c+v를 하고 있는 상황이 되어버렸다. 

![Untitled](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/Untitled%201.png)

결국 약 2시간 정도를 허비해 버린 채 기존에 만들었던 exploit 자동화 도구를 포기하고 빠르게 python으로 개인 PC에서 공격 코드를 실행하는 방향으로 변경했다.

이미 꽤 많은 취약점들이 발견되어 우리 서버에 공격이 들어왔지만, 수작업으로 열심히 flag를 인증 하는 작업과 다른 팀원들이 새로운 취약점을 찾아서 대회 초반까지는 상위권을 유지할 수 있었다.

![Untitled](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/Untitled%202.png)

대회 중반을 넘어서자 우리 팀 대회 서버의 root권한까지 탈취 당해 다수의 서비스에서 SLA 체크를 통과하지 못하는 사태가 발생하게 되었다. ~~문제 서버에 실행만 하면 root쉘을 주는 친구가 숨어 있을 줄은 몰랐지…~~

최종적으로 11위라는 순위로 대회를 마무리하게 됐다. 아쉬움도 많고 부족한 부분도 많았지만 루마니아에서의 CTF 참여는 좋은 경험이었고, 한 걸음 성장할 수 있는 발판이었다.

![FhOnHWNXEBY5drz.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/FhOnHWNXEBY5drz.jpg)

## 대회 끝! 이제 놀고 쉬자!!!

대회를 마치고 팀원들과 로비에서 기념 사진도 한 장 찍어줬다. 다시 찍으려면 루마니아까지 와야하니,,😂

![KakaoTalk_20221111_033905765_06.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/KakaoTalk_20221111_033905765_06.jpg)

![KakaoTalk_20221111_033905765.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/KakaoTalk_20221111_033905765.jpg)

대회를 마친 후 팀원들과 함께 택시를 타고 old town으로 이동했다. 의성이형(@zairo)이 알려주신 루마니아의 맛집 **Caru' cu bere** 에 가기 위해서 였다.

![20221110_200833.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_200833.jpg)

워낙 유명한 맛집이어서 그런건지 자리에 앉아서 주문하기까지 30분이 넘는 시간이 걸렸다. 1인당 1개의 메뉴를 시켰는데, 맥주를 마시려다 다른 이상한 걸 주문해버리는 사소한 실수도 있었지만, 함께 고생한 팀원들과 먹는 저녁 식사는 고생한 우리에게 정말 행복한 시간이었다.

<figure class="third">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_213546.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_215923.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_213550.jpg">
</figure>

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_213556.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221110_213602.jpg">
</figure>


그렇게 식사를 마치고 숙소에 돌아와서 한국 컵라면을 같이 끓여 먹자는 약속을 뒤로 한 채 피로를 이기지 못하고 다들 잠에 들었다. 

# 대회도 끝났겠다 잠도 잤겠다 이제 놀자ㅏ!!

대회가 끝나고 충분히 잠을 잔 팀원들은 하나 둘 일어나 놀 준비를 시작했다. 일찍 일어난 팀원들과 함께 조식을 먹고 몇몇 팀원과 함께 한 번 더 Defcamp 행사장에 가보기로 했다.

![20221111_073438.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_073438.jpg)

![20221111_072215.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_072215.jpg)

## 지하철을 타보자!

일정에 어느정도 여유도 생겼겠다 우리는 지하철에 도전해보기로 했다. 티켓을 구매해서 개찰구에 티켓을 넣는 형태였는데 2회권 부터 구매가 가능했다. 2회권 가격은 한화 1800원 정도! 편도 기준 900원 정도에 지하철을 이용할 수 있었다. 

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_130744.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_131016.jpg">
</figure>


![20221111_162556.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_162556.jpg)

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_161930.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_161938.jpg">
</figure>


## 이 자물쇠는 이제 제겁니다. 락픽 체험기!

Defcamp 행사장에 도착해서 가장 먼저 간 곳은 바로 락픽(Lock Pick)을 할 수 있도록 구성된 부스였다! 먼저 도착했던 유택(@R3dzone)이가 자물쇠를 따고 있길래 호다닥 따라가서 배워봤다. 쉬운 자물쇠는 금방 열렸지만 갑자기 분위기 **수갑…?** 수갑 열기까지 시도해봤지만 실패했다.. 저 아저씨는 머리핀으로 뭔가 휘끼휘끼 하더니 찰칵 풀리던데 그렇게 쉽게 배울 수 있는 기술은 아니었나 보다😂

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_140604.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_135446.jpg">
</figure>

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_141140.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_141300.jpg">
</figure>

주변 부스들도 구경하고 다양한 스티커들도 받으면서 빠르게 구경을 마치고 나오는데 어제 만난 레드불 차량이 또!! 옆에서 기념 사진 한 장 찍어줬다.

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_143815.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_143832.jpg">
</figure>

## 어머 이건 꼭 먹어야 해 LUCA!!!

루마니아에서 기억에 남는 음식 3가지를 정하자면 첫 번째가 LUCA일 정도로 간편하고, 맛있고, 저렴한 음식이었다. 정확히는 매장 이름이 LUCA였는데 루마니아의 simigerialuca라는 브랜드였다. 여기서 happy luca라는 음식을 시켰는데 어라 이 맛은..!? 약간 피자빵 같으면서도 핫도그의 느낌이 있는 그런 음식이었다! 안에 햄이 들어간 메뉴, 소시지가 들어간 메뉴 등등 다양한 종류가 있었는데, 개인적으로는 소시지, 머스타드, 케첩, 치즈가 들어간 happy luca가 제일 맛있었다. 

<figure class="half">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_160120.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_160425.jpg">
</figure>


# 다시 본격적으로 가보자 old town

다음 날 한국으로 가거나 다른 나라를 여행하는 친구들이 있어서, 다 같이 루마니아에 있을 수 있는 마지막 밤 11일 저녁, 우리는 다시 old town으로 향했다. 이쯤에서 *old town이 어떤 곳이길래 저렇게 자주 갈까* 생각하는 사람들을 위해 간단히 설명하자면 한국의 홍대 클럽거리와 신촌 그 중간 쯤 느낌이었다. 북적북적하고 사람도 많은 곳!

![Untitled](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/Untitled%203.png)

일단 부지런하게 놀기 위해 맛있는 걸 먹어야 하기 때문에 우리는 근처 식당에서 각자 먹고싶은 걸 시켰다. 난 까르보나라 파스타와 사워크림이 올라간 감자, 글랜피딕 15y 1잔과 맥주 1잔을 시켰다. 아래 사진에 나온 메뉴들을 다 합해서 97레이(한화 약 2.9만원 정도)였는데 가성비 있게 즐긴 것 같아서 괜찮았다.

![20221111_220030.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_220030.jpg)

유택이는 거대한 티본 스테이크를 주문했다. 나이프를 들고 찍은 사진이 인상적이었지만 유택이의 혼삿길을 위해 갤러리에 고이 보관해두도록 하겠다.

![20221111_220119.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_220119.jpg)

![20221111_220142.jpg](https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221111_220142.jpg)

## 루마니아의 클럽?! 좋지~

식사를 마친 후 우리는 가장 핫 한 번화가 쪽으로 이동했다. 갈수록 사람은 많아지고 양 옆에서 들리는 큰 음악 소리에 여기가 대충 한국의 홍대 클럽 거리겠군.. 하며 사람이 많아 보이는 한 클럽에 들어갔다. 신기하게도 여기는 입장료가 따로 없고 들어가서 본인이 마실 음료만 구매하면 되는 시스템이었다. 팀원들과 마지막 밤은 신나게! 놀았다.

<figure class="third">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221112_021826.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221112_024313.jpg">
    <img src="https://res.cloudinary.com/imreplay/image/upload/q_auto/part3/20221112_023503.jpg">
</figure>


> 해가 뜨기 전에 호다닥 숙소로 들어가며 함께 보내는 마지막 밤은 그렇게 지나갔다.