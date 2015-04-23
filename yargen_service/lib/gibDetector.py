#!/usr/bin/python

import pickle
import gib_detect_train
import os

class GibDetector(object):

	def __init__(self):
		#model_data = pickle.load(open('lib/gib_model.pki', 'rb'))
		fullpki = os.path.dirname(os.path.abspath(__file__))
		fullpki += "/gib_model.pki"
		model_data = pickle.load(open(fullpki, 'rb'))
		self.model_mat = model_data['mat']
		self.threshold = model_data['thresh']		
		
	def getRating(self, string):
		return gib_detect_train.avg_transition_prob(string, self.model_mat) > self.threshold

	def getScore(self, string):
		return round(gib_detect_train.avg_transition_prob(string, self.model_mat) / self.threshold, 2)
