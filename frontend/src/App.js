// Filename - App.js

// Importing modules
import React, { useState, useEffect } from "react";
import "./App.css";

function App() {
	// usestate for setting a javascript
	// object for storing and using data
	const [data, setdata] = useState({
		name: "",
		age: 0,
		date: "",
		programming: "",
	});

	// Using useEffect for single rendering
	useEffect(() => {
		// Using fetch to fetch the api from 
		// flask server it will be redirected to proxy
		fetch("/data").then((res) =>
			res.json().then((data) => {
				// Setting a data from api
				setdata({
					name: data.Name,
					age: data.Age,
					date: data.Date,
					programming: data.programming,
				});
			})
		);
	}, []);

	return (
		<div className="App">
			<header className="App-header">
				<h2>PQC demo</h2>
			</header>
			<center>
				{/* <div>
					<p>{data.name}</p>
					<p>{data.age}</p>
					<p>{data.date}</p>
					<p>{data.programming}</p>
				</div> */}
				<div className="content-Box">
					<div className="send-Box">
						<h2>Send</h2>
						<div class="fakeMenu">
							<div class="fakeButtons fakeClose"></div>
							<div class="fakeButtons fakeMinimize"></div>
							<div class="fakeButtons fakeZoom"></div>
						</div>
						<div class="fakeScreen">
							<form method="POST">
								<label>
									<p>Send:</p>
									<input type="text" name="input" />
								</label>
								&emsp;
								<input type="submit" value="Submit" />
							</form>
							{/* <p class="line4"><span class="cursor4">_</span></p> */}
						</div>
					</div>
					<div className="recieve-Box">
						<h2>Recieve</h2>
						<div class="fakeMenu">
							<div class="fakeButtons fakeClose"></div>
							<div class="fakeButtons fakeMinimize"></div>
							<div class="fakeButtons fakeZoom"></div>
						</div>
						<div class="fakeScreen">
							{/* <p class="line4"><span class="cursor4">_</span></p> */}
						</div>
					</div>
				</div>
			</center>
		</div>
	);
}

export default App;

