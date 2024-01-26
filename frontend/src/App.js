// Filename - App.js

// Importing modules
import React, { useState, useEffect, useRef } from "react";
import "./App.css";

function App() {

	const [msgs, setmsgs] = useState([]);
	const endOfMessagesRef = useRef(null);

	const addNewMsg = (msg) => {
		if(msgs.length > 0){
			setmsgs([...msgs.slice(0, -1), msg, <br/>]);
		}
		else{
			setmsgs([...msgs, msg, <br/>]);
		}
	};
	useEffect(() => {
        console.log("msgs:", msgs);
    }, [msgs]);

	useEffect(() => {
        if (endOfMessagesRef.current) {
            endOfMessagesRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [msgs]);

	// // Using useEffect for single rendering
	// useEffect(() => {
	// 	// Using fetch to fetch the api from 
	// 	// flask server it will be redirected to proxy
		// fetch("/data").then((res) =>
		// 	res.json().then((data) => {
		// 		// Setting a data from api
		// 		setdata({
		// 			name: data.Name,
		// 			age: data.Age,
		// 			date: data.Date,
		// 			programming: data.programming,
		// 		});
		// 		console.log(data);
		// 	})
		// );
	// }, []);

	const [inputValue, setInputValue] = useState('');
    const [cursorPosition, setCursorPosition] = useState(0);

    useEffect(() => {
        setCursorPosition(getTextWidth(inputValue));
    }, [inputValue]);

    const handleInputChange = (event) => {
        setInputValue(event.target.value);
    };

    const getTextWidth = (text) => {
        const canvas = document.createElement("canvas");
        const context = canvas.getContext("2d");
        context.font = '16px monospace';
        return context.measureText(text).width;
    };
	
	const inputRef = useRef(null);

    useEffect(() => {
        const handleKeyDown = (event) => {
            // 如果當前焦點已在 input 內，則不進行操作
            if (document.activeElement === inputRef.current) {
                return;
            }

            // 將焦點設定到 input 上
            inputRef.current.focus();

            // 防止在輸入時觸發其他鍵盤快捷鍵
            event.preventDefault();
        };

        // 添加事件監聽器
        document.addEventListener('keydown', handleKeyDown);

        // 清除事件監聽器
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, []);

	const handleSubmit = async (event) => {
        event.preventDefault();
		// try {
        //     const response = await fetch('/data', {
        //         method: 'GET',
        //         headers: {
        //             'Content-Type': 'application/json',
        //         },
        //         // body: JSON.stringify({ data: inputValue }),
        //     });

        //     if (!response.ok) {
        //         throw new Error('Network response was not ok');
        //     }

        //     await response.json().then((data) => {
		// 			// Setting a data from api
		// 			setdata({
		// 				name: data.Name,
		// 				age: data.Age,
		// 				date: data.Date,
		// 				programming: data.programming,
		// 			});
		// 		});
		// 	// console.log(responseData);
        //     // setResponse(responseData);
			
        //     setInputValue('');
        // } catch (error) {
        //     console.error('Error:', error);
        // }
		try {
            const response = await fetch('/handle_msg', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ msg: inputValue }),
            });
			
			// console.log(JSON.stringify({ data: inputValue }));
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const responseData = await response.json();
			console.log(responseData);
		
			addNewMsg(responseData.response);

            setInputValue('');
        } catch (error) {
            console.error('Error:', error);
        }
    };
	
	return (
		<div className="App">
			<header className="App-header">
				<h2>PQC demo</h2>
			</header>
			<center>
				<div className="content-Box">
					<div className="log-Box">
						<h2>Log</h2>
						<div className="fakeMenu">
							<div className="fakeButtons fakeClose"></div>
							<div className="fakeButtons fakeMinimize"></div>
							<div className="fakeButtons fakeZoom"></div>
						</div>
						<div className="fakeScreen logScreen">
							<div className="log">
								{msgs.map((msg, index) => (
									<p key={index}>{msg}</p>
								))}
								<div ref={endOfMessagesRef}></div>
							</div>
						</div>
					</div>
					<div className="send-Box">
						<h2>Send</h2>
						<div className="fakeMenu">
							<div className="fakeButtons fakeClose"></div>
							<div className="fakeButtons fakeMinimize"></div>
							<div className="fakeButtons fakeZoom"></div>
						</div>
						<div className="fakeScreen">
							<div className="form-container">
								<form onSubmit={handleSubmit}>
									<label>
										<div className="flex-container">
											<div>
												<span>&gt;&nbsp;</span>
											</div>
											<div className="inputBorder">
											<input className="msgInput" type="text" ref={inputRef} value={inputValue} onChange={handleInputChange} autoComplete="off" name="input" />
											<span className="cursor" style={{left: cursorPosition + 2}}>_</span>
											</div>
										</div>
									</label>
									&emsp;
									<input type="submit" value="Send" style={{display: 'none'}} />
								</form>
							</div>
						</div>
					</div>
				</div>
			</center>
		</div>
	);
}

export default App;

